"""Telegram channel monitor (Audit B3 — Phase 4.1).

For each organization, scrape the public ``t.me/s/<channel>`` web
preview of every monitored channel and emit:

- :class:`FraudFinding` rows for messages whose ``score_text()`` exceeds
  the configured threshold (crypto-giveaway / investment-scam style
  posts that mention the brand).
- :class:`ImpersonationFinding` rows when the channel handle itself
  scores against any registered :class:`VipProfile` alias / brand
  name (e.g. ``@argus_official_xyz`` impersonating the bank).

Why public web preview?
-----------------------
- Zero authentication required — Argus can ship to a customer without
  asking them to register a Telegram developer account, give us their
  phone number, or maintain a session file.
- Public-channel-only is the right scope for brand monitoring; private
  channels rarely host the public-facing scams we're trying to catch.
- For organizations that need *private*-channel coverage, a Telethon-
  based path can be added behind the same interface — the public
  matcher in this module is already store-of-record for fraud + impers
  scoring, so a private-mode adapter would just call the same scoring
  helpers with messages it received via MTProto.

Configuration
-------------
Channels to monitor are read from
``Organization.settings["telegram_monitor_channels"]`` (a list of
strings, channel handles without the leading ``@``). When the field is
absent the monitor is a no-op for that org.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

import aiohttp
from bs4 import BeautifulSoup
from rapidfuzz import fuzz
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.brand import BrandTerm, BrandTermKind
from src.models.fraud import (
    FraudChannel,
    FraudFinding,
    FraudKind,
    FraudState,
)
from src.models.social import (
    ImpersonationFinding,
    ImpersonationKind,
    ImpersonationState,
    SocialPlatform,
    VipProfile,
)
from src.models.threat import Organization
from src.social.fraud import score_text as fraud_score_text


_logger = logging.getLogger(__name__)


TELEGRAM_PREVIEW_URL = "https://t.me/s/{channel}"
DEFAULT_FRAUD_THRESHOLD = 0.4
DEFAULT_IMPERSONATION_THRESHOLD = 75
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


@dataclass
class TelegramMessage:
    channel: str
    text: str
    url: str
    published_at: datetime | None = None


@dataclass
class ScanReport:
    organization_id: uuid.UUID
    channels_scanned: int
    messages_seen: int
    fraud_findings_created: int
    fraud_findings_seen_again: int
    impersonations_created: int
    errors: list[str] = field(default_factory=list)


# --- Fetch / parse ------------------------------------------------------


async def _fetch_channel_html(
    session: aiohttp.ClientSession, channel: str
) -> str | None:
    url = TELEGRAM_PREVIEW_URL.format(channel=channel)
    try:
        async with session.get(
            url,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return None
            return await resp.text()
    except Exception as e:  # noqa: BLE001
        _logger.warning("telegram fetch failed for %s: %s", channel, e)
        return None


def _parse_messages(channel: str, html: str) -> list[TelegramMessage]:
    """Extract message text + permalinks from the preview HTML.

    The preview emits a `tgme_widget_message_wrap` per message; very
    short messages (< 10 chars) are discarded as ack/emoji noise.
    """
    soup = BeautifulSoup(html, "html.parser")
    out: list[TelegramMessage] = []
    for el in soup.select("div.tgme_widget_message_wrap"):
        text_el = el.select_one("div.tgme_widget_message_text")
        if not text_el:
            continue
        text = text_el.get_text(" ", strip=True)
        if not text or len(text) < 10:
            continue
        link_el = el.select_one("a.tgme_widget_message_date")
        url = (
            link_el["href"]
            if link_el is not None and link_el.get("href")
            else TELEGRAM_PREVIEW_URL.format(channel=channel)
        )
        time_el = el.select_one("time")
        published_at = None
        if time_el is not None and time_el.get("datetime"):
            try:
                published_at = datetime.fromisoformat(
                    time_el["datetime"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        out.append(
            TelegramMessage(
                channel=channel,
                text=text,
                url=url,
                published_at=published_at,
            )
        )
    return out


# --- Persistence -------------------------------------------------------


async def _persist_fraud(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    msg: TelegramMessage,
    score,
) -> FraudFinding | None:
    """Insert-or-touch one fraud finding. Returns the new row, or
    ``None`` if the (org, channel, message_url) tuple already exists.
    """
    try:
        kind = FraudKind(score.kind)
    except ValueError:
        kind = FraudKind.OTHER

    existing = (
        await db.execute(
            select(FraudFinding).where(
                and_(
                    FraudFinding.organization_id == organization_id,
                    FraudFinding.channel == FraudChannel.TELEGRAM.value,
                    FraudFinding.target_identifier == msg.url,
                )
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.score = max(existing.score, float(score.score))
        existing.rationale = score.rationale
        existing.matched_keywords = list(score.matched_keywords)
        existing.matched_brand_terms = list(score.matched_brand_terms)
        return None

    finding = FraudFinding(
        organization_id=organization_id,
        kind=kind.value,
        channel=FraudChannel.TELEGRAM.value,
        target_identifier=msg.url,
        title=f"Telegram: @{msg.channel}",
        excerpt=msg.text[:500],
        matched_brand_terms=list(score.matched_brand_terms),
        matched_keywords=list(score.matched_keywords),
        score=float(score.score),
        rationale=score.rationale,
        detected_at=msg.published_at or datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw={"channel": msg.channel, "extra": score.extra},
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


def _channel_impersonation_score(
    channel_handle: str,
    *,
    vip_profiles: Iterable[VipProfile],
    brand_names: Iterable[str],
) -> tuple[int, str | None, str | None, uuid.UUID | None]:
    """Return ``(best_score, matched_term, kind, vip_profile_id)``.

    ``kind`` is ``"vip"`` if the best match was a VIP alias / full-
    name, else ``"brand"`` if a brand-name term, else ``None``.
    ``vip_profile_id`` is the matching VIP's id when ``kind == "vip"``.
    """
    handle_l = channel_handle.lower().lstrip("@")
    if not handle_l:
        return 0, None, None, None

    best_score = 0
    best_term: str | None = None
    best_kind: str | None = None
    best_vip_id: uuid.UUID | None = None

    for vp in vip_profiles:
        candidates = [vp.full_name or ""] + list(vp.aliases or [])
        for c in candidates:
            c_l = (c or "").lower().strip()
            if len(c_l) < 4:
                continue
            score = fuzz.partial_ratio(c_l, handle_l)
            if score > best_score:
                best_score = score
                best_term = c
                best_kind = "vip"
                best_vip_id = vp.id

    for b in brand_names:
        b_l = (b or "").lower().strip()
        if len(b_l) < 4:
            continue
        score = fuzz.partial_ratio(b_l, handle_l)
        if score > best_score:
            best_score = score
            best_term = b
            best_kind = "brand"
            best_vip_id = None

    return best_score, best_term, best_kind, best_vip_id


async def _persist_impersonation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    channel: str,
    score: int,
    matched_term: str,
    kind: str,
    vip_profile_id: uuid.UUID | None,
) -> ImpersonationFinding | None:
    handle = channel.lstrip("@")
    target_url = f"https://t.me/{handle}"
    impers_kind = (
        ImpersonationKind.EXECUTIVE.value
        if kind == "vip"
        else ImpersonationKind.BRAND_ACCOUNT.value
    )
    existing = (
        await db.execute(
            select(ImpersonationFinding).where(
                and_(
                    ImpersonationFinding.organization_id == organization_id,
                    ImpersonationFinding.platform == SocialPlatform.TELEGRAM.value,
                    ImpersonationFinding.candidate_handle == handle,
                    ImpersonationFinding.kind == impers_kind,
                )
            )
        )
    ).scalar_one_or_none()
    score_f = float(score) / 100.0
    if existing is not None:
        existing.aggregate_score = max(existing.aggregate_score, score_f)
        existing.handle_similarity = max(existing.handle_similarity, score_f)
        return None

    finding = ImpersonationFinding(
        organization_id=organization_id,
        vip_profile_id=vip_profile_id,
        platform=SocialPlatform.TELEGRAM.value,
        candidate_handle=handle,
        candidate_url=target_url,
        kind=impers_kind,
        name_similarity=score_f if kind == "vip" else 0.0,
        handle_similarity=score_f,
        bio_similarity=0.0,
        photo_similarity=None,
        aggregate_score=score_f,
        signals=[f"telegram_handle:{kind}_match", f"matched_term={matched_term}"],
        state=ImpersonationState.OPEN.value,
        detected_at=datetime.now(timezone.utc),
        raw={
            "source": "telegram_monitor",
            "matched_term": matched_term,
            "matched_term_kind": kind,
            "fuzz_partial_ratio": score,
        },
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


# --- Top-level scan orchestration --------------------------------------


def _channels_for_org(org: Organization) -> list[str]:
    settings = (org.settings or {}) if hasattr(org, "settings") else {}
    raw = (settings or {}).get("telegram_monitor_channels") or []
    if isinstance(raw, str):
        return [s.strip().lstrip("@") for s in raw.split(",") if s.strip()]
    if isinstance(raw, list):
        return [str(s).strip().lstrip("@") for s in raw if s]
    return []


async def scan_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    fraud_threshold: float | None = None,
    impersonation_threshold: int | None = None,
    auto_case_high: float | None = None,
    fetch_html=_fetch_channel_html,
) -> ScanReport:
    """Run a single monitoring cycle for one organization.

    ``fetch_html`` is overridable so tests inject canned HTML without
    hitting the live web. Per-channel failures are isolated.
    """
    if (
        fraud_threshold is None or impersonation_threshold is None
        or auto_case_high is None
    ):
        from src.core.detector_config import load_social_thresholds

        bundle = await load_social_thresholds(db, organization_id, "telegram")
        if fraud_threshold is None:
            fraud_threshold = bundle.fraud_threshold
        if impersonation_threshold is None:
            impersonation_threshold = bundle.impersonation_threshold
        if auto_case_high is None:
            auto_case_high = bundle.auto_case_high

    org = await db.get(Organization, organization_id)
    if org is None:
        return ScanReport(
            organization_id=organization_id,
            channels_scanned=0,
            messages_seen=0,
            fraud_findings_created=0,
            fraud_findings_seen_again=0,
            impersonations_created=0,
        )

    channels = _channels_for_org(org)
    if not channels:
        return ScanReport(
            organization_id=organization_id,
            channels_scanned=0,
            messages_seen=0,
            fraud_findings_created=0,
            fraud_findings_seen_again=0,
            impersonations_created=0,
        )

    brand_terms = (
        await db.execute(
            select(BrandTerm).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    brand_term_values = [t.value for t in brand_terms]
    brand_name_values = [
        t.value for t in brand_terms if t.kind == BrandTermKind.NAME.value
    ]

    vip_profiles = (
        await db.execute(
            select(VipProfile).where(VipProfile.organization_id == organization_id)
        )
    ).scalars().all()

    fraud_created = 0
    fraud_seen = 0
    impers_created = 0
    messages_seen = 0
    errors: list[str] = []

    async with aiohttp.ClientSession() as http:
        for channel in channels:
            # Channel handle → impersonation score
            handle_score, matched_term, kind, vip_profile_id = (
                _channel_impersonation_score(
                    channel,
                    vip_profiles=vip_profiles,
                    brand_names=brand_name_values,
                )
            )
            if (
                handle_score >= impersonation_threshold
                and matched_term
                and kind
            ):
                created = await _persist_impersonation(
                    db,
                    organization_id=organization_id,
                    channel=channel,
                    score=handle_score,
                    matched_term=matched_term,
                    kind=kind,
                    vip_profile_id=vip_profile_id,
                )
                if created is not None:
                    impers_created += 1

            html = await fetch_html(http, channel)
            if html is None:
                errors.append(f"{channel}: fetch failed")
                continue
            messages = _parse_messages(channel, html)
            messages_seen += len(messages)
            for msg in messages:
                score = fraud_score_text(msg.text, brand_terms=brand_term_values)
                if score.score < fraud_threshold:
                    continue
                created = await _persist_fraud(
                    db,
                    organization_id=organization_id,
                    msg=msg,
                    score=score,
                )
                if created is None:
                    fraud_seen += 1
                else:
                    fraud_created += 1
                    await _maybe_auto_link(
                        db,
                        organization_id=organization_id,
                        finding=created,
                        score=score.score,
                        auto_case_high=auto_case_high,
                    )

    return ScanReport(
        organization_id=organization_id,
        channels_scanned=len(channels),
        messages_seen=messages_seen,
        fraud_findings_created=fraud_created,
        fraud_findings_seen_again=fraud_seen,
        impersonations_created=impers_created,
        errors=errors,
    )


async def _maybe_auto_link(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    finding: FraudFinding,
    score: float,
    auto_case_high: float = 0.7,
) -> None:
    """Promote high-score fraud to a Case via the shared auto-link
    helper. Best-effort; never rolls back the finding."""
    try:
        from src.cases.auto_link import auto_link_finding

        sev = "high" if score >= auto_case_high else "medium"
        await auto_link_finding(
            db,
            organization_id=organization_id,
            finding_type="fraud_finding",
            finding_id=finding.id,
            severity=sev,
            title=f"Telegram fraud: {finding.title or finding.target_identifier}",
            summary=(
                finding.rationale or "Telegram message scored above the fraud "
                "threshold."
            ),
            event_kind="data_leakage",
            dedup_key=f"fraud:telegram:{finding.target_identifier}",
            tags=("fraud", "telegram"),
        )
    except Exception:  # noqa: BLE001
        _logger.exception(
            "auto_link_finding failed for telegram fraud %s", finding.id
        )


__all__ = [
    "TelegramMessage",
    "ScanReport",
    "scan_organization",
    "DEFAULT_FRAUD_THRESHOLD",
    "DEFAULT_IMPERSONATION_THRESHOLD",
]
