"""Live page-probe orchestrator.

Pulls a suspect domain via an injectable fetcher (default: aiohttp,
production: Playwright), runs the classifier, stores HTML + screenshot
in Evidence Vault, and persists a :class:`LiveProbe` row.

The fetcher is injectable so tests use a fake.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.models.brand import BrandTerm, SuspectDomain
from src.models.evidence import EvidenceBlob, EvidenceKind
from src.models.live_probe import LiveProbe, LiveProbeVerdict
from src.storage import evidence_store

from .classifier import (
    ClassificationResult,
    Classifier,
    FetchedPage,
    get_classifier,
)


_logger = logging.getLogger(__name__)


Fetcher = Callable[[str], Awaitable[FetchedPage]]


# --- Default aiohttp fetcher ------------------------------------------


async def default_fetcher(domain: str) -> FetchedPage:
    """Resolve to https:// then http://, follow up to 5 redirects, 10 s budget.

    Production should swap to Playwright for JS-rendered phishing kits.

    Adversarial audit D-11 — every URL is run through ``url_safety``
    before the request opens, so a brand permutation that resolves to
    127.0.0.1 / 169.254.169.254 / RFC1918 cannot be probed.
    """
    import aiohttp

    from src.core.url_safety import UnsafeUrlError, assert_safe_url

    timeout = aiohttp.ClientTimeout(total=10)
    headers = {
        "User-Agent": "Argus-LiveProbe/1.0 (+https://argus.gaigentic.ai)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    url = f"https://{domain}"
    err: str | None = None
    for scheme_url in (f"https://{domain}", f"http://{domain}"):
        try:
            await asyncio.to_thread(assert_safe_url, scheme_url, allow_http=True)
        except UnsafeUrlError as exc:
            err = f"blocked_unsafe_url: {exc}"
            continue
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                trust_env=False,
            ) as sess:
                async with sess.get(scheme_url, allow_redirects=True, max_redirects=5) as resp:
                    body = await resp.text(errors="replace")
                    return FetchedPage(
                        domain=domain,
                        url=scheme_url,
                        final_url=str(resp.url),
                        http_status=resp.status,
                        title=None,
                        html=body[:512_000],  # cap at ~500 KB
                    )
        except Exception as e:  # noqa: BLE001
            err = str(e)[:300]
            continue
    return FetchedPage(
        domain=domain,
        url=url,
        final_url=url,
        http_status=None,
        title=None,
        html="",
        error_message=err or "fetch failed",
    )


# --- Test injection hooks ---------------------------------------------


_TEST_FETCHER: Fetcher | None = None


def set_test_fetcher(fn: Fetcher | None) -> None:
    global _TEST_FETCHER
    _TEST_FETCHER = fn


def reset_test_fetcher() -> None:
    set_test_fetcher(None)


# --- Orchestrator -----------------------------------------------------


async def _store_evidence(
    db: AsyncSession,
    organization_id: uuid.UUID,
    domain: str,
    html: bytes,
    screenshot: bytes | None,
) -> tuple[str | None, str | None]:
    """Persist HTML + screenshot bytes in MinIO + DB. Returns (html_sha, shot_sha)."""
    bucket = settings.evidence.bucket
    html_sha = None
    shot_sha = None

    if html:
        html_sha = evidence_store.sha256_of(html)
        key = evidence_store.storage_key(str(organization_id), html_sha)
        try:
            evidence_store.ensure_bucket(bucket)
            if not evidence_store.exists(bucket, key):
                evidence_store.put(bucket, key, html, "text/html")
        except Exception as e:  # noqa: BLE001
            _logger.warning("Evidence MinIO unreachable; skipping HTML upload: %s", e)
            html_sha = None
        else:
            existing = (
                await db.execute(
                    select(EvidenceBlob).where(
                        and_(
                            EvidenceBlob.organization_id == organization_id,
                            EvidenceBlob.sha256 == html_sha,
                        )
                    )
                )
            ).scalar_one_or_none()
            if existing is None:
                db.add(
                    EvidenceBlob(
                        organization_id=organization_id,
                        sha256=html_sha,
                        size_bytes=len(html),
                        content_type="text/html",
                        original_filename=f"{domain}.html",
                        kind=EvidenceKind.HTML_SNAPSHOT.value,
                        s3_bucket=bucket,
                        s3_key=key,
                        captured_at=datetime.now(timezone.utc),
                        capture_source="live_probe",
                    )
                )

    if screenshot:
        shot_sha = evidence_store.sha256_of(screenshot)
        key = evidence_store.storage_key(str(organization_id), shot_sha)
        try:
            evidence_store.ensure_bucket(bucket)
            if not evidence_store.exists(bucket, key):
                evidence_store.put(bucket, key, screenshot, "image/png")
        except Exception as e:  # noqa: BLE001
            _logger.warning("Evidence MinIO unreachable; skipping screenshot: %s", e)
            shot_sha = None
        else:
            existing = (
                await db.execute(
                    select(EvidenceBlob).where(
                        and_(
                            EvidenceBlob.organization_id == organization_id,
                            EvidenceBlob.sha256 == shot_sha,
                        )
                    )
                )
            ).scalar_one_or_none()
            if existing is None:
                db.add(
                    EvidenceBlob(
                        organization_id=organization_id,
                        sha256=shot_sha,
                        size_bytes=len(screenshot),
                        content_type="image/png",
                        original_filename=f"{domain}.png",
                        kind=EvidenceKind.SCREENSHOT.value,
                        s3_bucket=bucket,
                        s3_key=key,
                        captured_at=datetime.now(timezone.utc),
                        capture_source="live_probe",
                    )
                )

    return html_sha, shot_sha


async def probe_suspect(
    db: AsyncSession,
    organization_id: uuid.UUID,
    suspect_id: uuid.UUID,
    *,
    classifier_name: str = "heuristic-v1",
    fetcher: Fetcher | None = None,
) -> LiveProbe:
    suspect = await db.get(SuspectDomain, suspect_id)
    if suspect is None or suspect.organization_id != organization_id:
        raise LookupError("Suspect not found in this organization")

    fetcher_fn = fetcher or _TEST_FETCHER or default_fetcher
    page = await fetcher_fn(suspect.domain)

    classifier = get_classifier(classifier_name)
    terms_rows = (
        await db.execute(
            select(BrandTerm).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    brand_term_strings = [t.value for t in terms_rows]

    result: ClassificationResult = classifier.classify(page, brand_terms=brand_term_strings)

    html_sha, shot_sha = await _store_evidence(
        db,
        organization_id,
        suspect.domain,
        (page.html or "").encode("utf-8", errors="replace"),
        page.screenshot_bytes,
    )

    probe = LiveProbe(
        organization_id=organization_id,
        suspect_domain_id=suspect.id,
        domain=suspect.domain,
        url=page.url,
        fetched_at=datetime.now(timezone.utc),
        http_status=page.http_status,
        final_url=page.final_url,
        title=page.title,
        html_evidence_sha256=html_sha,
        screenshot_evidence_sha256=shot_sha,
        verdict=result.verdict.value,
        classifier_name=classifier.name,
        confidence=result.confidence,
        signals=result.signals,
        matched_brand_terms=result.matched_brand_terms,
        rationale=result.rationale,
        error_message=page.error_message,
    )
    db.add(probe)
    await db.flush()
    return probe


__all__ = [
    "default_fetcher",
    "probe_suspect",
    "set_test_fetcher",
    "reset_test_fetcher",
]
