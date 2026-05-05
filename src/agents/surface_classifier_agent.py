"""Surface classifier agent.

Walks every Asset whose ``ai_classification`` is null (or stale) and
populates a structured tag bundle:

    {
        "environment": "prod" | "staging" | "dev" | "test" | "internal" | "unknown",
        "role": "admin" | "api" | "marketing" | "auth" | "cdn" | "storage" | "other",
        "tags": ["wordpress", "exposed-admin-panel", "cdn-fronted", ...],
        "confidence": 0.0..1.0,
        "rationale": "..."
    }

Two-pass strategy:

  1. **Heuristic pass** — rules over hostname tokens + httpx tech stack
     + status code. Fast, deterministic, catches the obvious cases
     (``staging.* / *-admin.* / api.*``). Always runs, fills
     ``ai_classification`` even when the LLM is unavailable.

  2. **LLM pass** — when an LLM provider is configured AND the heuristic
     confidence is < 0.6, dispatch a structured-output call. Strict
     JSON, bounded tokens. Falls back gracefully on any failure.

The agent never invents tags from thin air — every classification
includes a rationale that references at least one observed signal.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.llm.providers import LLMNotConfigured, LLMTransportError, get_provider
from src.models.threat import Asset

_logger = logging.getLogger(__name__)

# How long a classification is considered fresh.
_FRESH_DAYS = 30


_TOKEN_ROLES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(admin|console|cpanel|wp-?admin|portal)\b"), "admin"),
    (re.compile(r"\b(api|graphql|rest|gateway|grpc)\b"), "api"),
    (re.compile(r"\b(auth|sso|login|signin|oidc|oauth|saml)\b"), "auth"),
    (re.compile(r"\b(cdn|static|assets|media|images?|img)\b"), "cdn"),
    (re.compile(r"\b(s3|storage|backup|files?|upload)\b"), "storage"),
    (re.compile(r"\b(www|blog|news|marketing|landing)\b"), "marketing"),
    (re.compile(r"\b(mail|smtp|imap|webmail|exchange)\b"), "mail"),
    (re.compile(r"\b(vpn|remote|gateway|firewall)\b"), "vpn"),
    (re.compile(r"\b(jenkins|jira|gitlab|bitbucket|nexus|sonarqube|grafana|kibana)\b"), "internal-tool"),
]


_TOKEN_ENV: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(stage|staging|stg|preview|preprod)\b"), "staging"),
    (re.compile(r"\b(dev|develop|sandbox)\b"), "dev"),
    (re.compile(r"\b(test|qa|uat)\b"), "test"),
    (re.compile(r"\b(internal|intra|corp|priv|local)\b"), "internal"),
    (re.compile(r"\b(prod|production|live)\b"), "prod"),
]


def _heuristic_classify(asset: Asset) -> dict[str, Any]:
    """Best-effort classification from observable signals only."""
    name = (asset.value or "").lower()
    tokens = name.replace("-", " ").replace(".", " ")
    details = asset.details or {}
    http = details.get("http") or {}
    tech = [t.lower() for t in (http.get("tech") or []) if isinstance(t, str)]
    title = (http.get("title") or "").lower()
    status = http.get("status_code")
    ports = [p.get("port") for p in (details.get("ports") or []) if isinstance(p, dict)]

    # Environment.
    env = "unknown"
    env_signal = None
    for pat, label in _TOKEN_ENV:
        if pat.search(tokens):
            env = label
            env_signal = pat.pattern
            break
    if env == "unknown":
        # If the parent domain explicitly says "internal" or the asset is
        # only on RFC1918 IPs we can flag internal.
        ips = http.get("ips") or details.get("dns_detail", {}).get("a") or []
        if any(
            (
                isinstance(ip, str)
                and (
                    ip.startswith("10.")
                    or ip.startswith("192.168.")
                    or ip.startswith("172.16.")
                    or ip.startswith("172.17.")
                    or ip.startswith("172.18.")
                    or ip.startswith("172.19.")
                    or ip.startswith("172.2")
                    or ip.startswith("172.30.")
                    or ip.startswith("172.31.")
                )
            )
            for ip in ips
        ):
            env = "internal"
            env_signal = "RFC1918 IP"
        elif env == "unknown":
            env = "prod"  # default presumption
            env_signal = "default (no env token in name)"

    # Role.
    role = "other"
    role_signal: str | None = None
    for pat, label in _TOKEN_ROLES:
        if pat.search(tokens):
            role = label
            role_signal = pat.pattern
            break
    if role == "other":
        if "wordpress" in tech or "wordpress" in title:
            role = "marketing"
            role_signal = "WordPress detected"
        elif any(t in tech for t in ("nginx", "apache", "iis")) and 80 in ports:
            role = "marketing"  # generic web
            role_signal = "generic web stack"
        elif 22 in ports and 80 not in ports and 443 not in ports:
            role = "internal-tool"
            role_signal = "SSH only"

    # Tags — descriptive bundle.
    tags: list[str] = []
    for t in tech[:6]:
        tags.append(t)
    if 22 in ports:
        tags.append("ssh-open")
    if 3389 in ports:
        tags.append("rdp-open")
    if 5900 in ports:
        tags.append("vnc-open")
    if status and 200 <= status < 300:
        tags.append("publicly-accessible")
    elif status in (401, 403):
        tags.append("auth-gated")
    if (details.get("tls") or {}).get("grade") in ("F", "C"):
        tags.append("weak-tls")
    if ports and any(p in ports for p in (8080, 8443, 7001, 9090)):
        tags.append("non-standard-web-port")

    # Confidence: combine signal strengths.
    conf = 0.4
    if env_signal and env_signal != "default (no env token in name)":
        conf += 0.2
    if role_signal:
        conf += 0.2
    if tech:
        conf += 0.1
    conf = min(conf, 0.95)

    rationale_bits = []
    if env_signal:
        rationale_bits.append(f"environment={env} via {env_signal}")
    else:
        rationale_bits.append(f"environment={env}")
    if role_signal:
        rationale_bits.append(f"role={role} via {role_signal}")
    else:
        rationale_bits.append(f"role={role}")
    if tech:
        rationale_bits.append(f"tech={'+'.join(tech[:3])}")
    if status:
        rationale_bits.append(f"http={status}")
    rationale = "; ".join(rationale_bits)

    return {
        "environment": env,
        "role": role,
        "tags": list(dict.fromkeys(tags))[:10],  # dedup, cap
        "confidence": round(conf, 2),
        "rationale": rationale,
        "source": "heuristic",
    }


async def _llm_refine(
    provider, asset: Asset, baseline: dict[str, Any]
) -> dict[str, Any] | None:
    """Ask the LLM to refine a low-confidence classification. Strict JSON
    output. Returns None on any failure so the caller falls back to the
    heuristic."""
    system = (
        "You classify a single internet-exposed asset for a security team. "
        "Output ONE line of strict JSON with keys: environment "
        "(prod/staging/dev/test/internal/unknown), role "
        "(admin/api/auth/cdn/storage/marketing/mail/vpn/internal-tool/other), "
        "tags (array of <=10 lowercase strings, each 1..32 chars), "
        "confidence (0..1), rationale (<=200 chars). No prose. No markdown."
    )
    details = asset.details or {}
    http = details.get("http") or {}
    user = (
        f"asset.value: {asset.value}\n"
        f"asset_type: {asset.asset_type}\n"
        f"http.status_code: {http.get('status_code')}\n"
        f"http.title: {http.get('title')}\n"
        f"http.tech: {http.get('tech') or []}\n"
        f"ports: {[p.get('port') for p in (details.get('ports') or []) if isinstance(p, dict)][:10]}\n"
        f"tls.grade: {(details.get('tls') or {}).get('grade')}\n"
        f"heuristic_baseline: {json.dumps(baseline)}\n"
    )
    try:
        text = (await provider.call(system, user) or "").strip()
        if not text:
            return None
        # Strip ```json fences if present.
        if text.startswith("```"):
            text = re.sub(r"^```[a-z]*\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        obj = json.loads(text)
        if not isinstance(obj, dict):
            return None
        # Sanitize.
        env = (obj.get("environment") or "unknown").lower()
        role = (obj.get("role") or "other").lower()
        tags = obj.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        clean_tags = [str(t).lower()[:32] for t in tags if isinstance(t, (str, int, float))][:10]
        try:
            conf = float(obj.get("confidence") or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(conf, 1.0))
        rationale = str(obj.get("rationale") or "")[:200]
        return {
            "environment": env,
            "role": role,
            "tags": clean_tags,
            "confidence": round(conf, 2),
            "rationale": rationale,
            "source": "llm",
        }
    except (LLMTransportError, json.JSONDecodeError, Exception) as e:  # noqa: BLE001
        _logger.warning("classifier LLM call failed for asset %s: %s", asset.id, e)
        return None


async def classify_org_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    use_llm: bool = True,
    only_unclassified: bool = False,
    asset_ids: list[uuid.UUID] | None = None,
) -> dict[str, int]:
    """Classify assets for ``org_id``. Returns a summary dict."""
    qs = select(Asset).where(Asset.organization_id == org_id)
    if asset_ids:
        qs = qs.where(Asset.id.in_(asset_ids))
    if only_unclassified:
        cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESH_DAYS)
        qs = qs.where(
            or_(
                Asset.ai_classified_at.is_(None),
                Asset.ai_classified_at < cutoff,
            )
        )
    rows = (await db.execute(qs)).scalars().all()

    provider = None
    if use_llm:
        try:
            provider = get_provider(settings.llm)
        except LLMNotConfigured:
            provider = None
        except Exception as e:  # noqa: BLE001
            _logger.warning("classifier: provider init failed: %s", e)
            provider = None

    classified = 0
    llm_used = 0
    llm_failed = 0
    now = datetime.now(timezone.utc)

    for a in rows:
        baseline = _heuristic_classify(a)
        final = baseline
        if provider is not None and baseline["confidence"] < 0.6:
            refined = await _llm_refine(provider, a, baseline)
            if refined is not None:
                final = refined
                llm_used += 1
            else:
                llm_failed += 1
        a.ai_classification = final
        a.ai_classified_at = now
        classified += 1

    await db.commit()
    return {
        "classified": classified,
        "llm_used": llm_used,
        "llm_failed": llm_failed,
        "total_assets": len(rows),
    }


__all__ = ["classify_org_assets"]
