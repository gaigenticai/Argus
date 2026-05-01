"""Curated Telegram channels — Iranian / Arabic ransomware + hacktivist
clusters tracked publicly by threat-intel researchers (P3 #3.10).

The list is intentionally conservative — every entry has been seen
referenced in *public* security-vendor reporting (Recorded Future,
Mandiant, Microsoft Threat Intel, Group-IB, Check Point, Cybereason).
We do not list operator-private channels or any channel whose
membership requires social-engineering tradecraft to obtain — that
crosses operational-security boundaries this codebase doesn't take.

When a channel is taken down or rebranded, that's a frequent occurrence
on Telegram — the entry is preserved with ``status="defunct"`` so that
historical references in saved alerts continue to resolve, and the
collector skips it on live runs.

Operators add their own channels at runtime by inserting rows into
``telegram_channels`` (the DB-backed table is owned by the worker that
runs the collector, not by this module — this module is just the
seed catalog).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class CuratedChannel:
    """One curated channel.

    ``cluster`` is a short tag the dashboard groups by; ``actor_link``
    points at the actor we attribute the channel to (when known); the
    free-text ``rationale`` is what we surface to the analyst in the
    monitor UI so they understand why this channel is on the list.
    """
    handle: str             # @-less channel handle
    cluster: str            # "iranian-apt" / "arabic-hacktivist" /
                            # "ransomware-leak" / "carding"
    language: Literal["fa", "ar", "en", "mixed"]
    rationale: str
    actor_link: str | None = None
    status: Literal["active", "defunct", "private"] = "active"
    region_focus: list[str] | None = None    # ["IL", "GCC", "US"]…

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "cluster": self.cluster,
            "language": self.language,
            "rationale": self.rationale,
            "actor_link": self.actor_link,
            "status": self.status,
            "region_focus": list(self.region_focus or []),
        }


# ── Iranian / IRGC-aligned clusters ────────────────────────────────


_IRANIAN: list[CuratedChannel] = [
    CuratedChannel(
        handle="cyberav3ngers",
        cluster="iranian-apt",
        language="en",
        rationale=(
            "IRGC-linked Cyber Av3ngers OT-targeting cluster — "
            "publicly claims attacks on water / energy / manufacturing "
            "ICS in IL + GCC. Posts named-victim exfil claims and OT "
            "screenshots."
        ),
        actor_link="cyber_avengers",
        region_focus=["IL", "GCC"],
    ),
    CuratedChannel(
        handle="predatory_sparrow",
        cluster="iranian-apt",
        language="en",
        rationale=(
            "Predatory Sparrow / Gonjeshke Darande — disrupts Iranian "
            "infrastructure (steel mills, gas stations, banks). Public "
            "claims of opposing IRGC operations."
        ),
        actor_link="predatory_sparrow",
        region_focus=["IR"],
    ),
    CuratedChannel(
        handle="moses_staff_official",
        cluster="iranian-apt",
        language="en",
        rationale=(
            "Moses Staff (Cobalt Sapling) leak channel — Israeli "
            "victim org dumps; pivots to GCC consultancies that work "
            "with Israeli partners."
        ),
        actor_link="moses_staff",
        region_focus=["IL", "GCC"],
    ),
    CuratedChannel(
        handle="muddywater_log",
        cluster="iranian-apt",
        language="fa",
        rationale=(
            "Persian-language MuddyWater (TA450 / Mango Sandstorm) "
            "telemetry mentions — channel reposts target IPs and "
            "phishing lures targeting Middle-East banks + telcos."
        ),
        actor_link="muddywater",
        region_focus=["GCC", "TR"],
        status="private",  # Telethon-required; not publicly browsable
    ),
]


# ── Arabic-language hacktivist + carding clusters ──────────────────


_ARABIC: list[CuratedChannel] = [
    CuratedChannel(
        handle="anonghost_official",
        cluster="arabic-hacktivist",
        language="ar",
        rationale=(
            "AnonGhost / pro-Palestine hacktivism — DDoS-as-a-statement "
            "against IL + GCC normalisation-track entities. Frequently "
            "claims credit minutes after attacks; useful tipoff signal."
        ),
        actor_link="anonghost",
        region_focus=["IL", "GCC", "EG"],
    ),
    CuratedChannel(
        handle="yemeni_cyber_army",
        cluster="arabic-hacktivist",
        language="ar",
        rationale=(
            "Yemeni Cyber Army — Houthi-aligned Arabic-language ops, "
            "active against Saudi + UAE targets in maritime, "
            "telecoms, defence."
        ),
        actor_link="yemeni_cyber_army",
        region_focus=["SA", "AE"],
    ),
    CuratedChannel(
        handle="arab_carding_lounge",
        cluster="carding",
        language="ar",
        rationale=(
            "Arabic carding / CC-sharing channel — historical roots in "
            "dev-point + sec4ever; chatter migrated here. Useful for "
            "stolen-card BIN sweeps for GCC issuers."
        ),
        region_focus=["SA", "AE", "EG", "JO"],
    ),
    CuratedChannel(
        handle="arab_breach_archive",
        cluster="leaks",
        language="ar",
        rationale=(
            "Arabic-language reposter of BreachForums-successor dumps. "
            "Often surfaces credential dumps for GCC b2c services hours "
            "before the Western community catches them."
        ),
        region_focus=["SA", "AE", "QA", "KW"],
    ),
]


# ── English-language ransomware leak-channel mirrors ────────────────


_RANSOMWARE: list[CuratedChannel] = [
    CuratedChannel(
        handle="ransomware_news_mirror",
        cluster="ransomware-leak",
        language="en",
        rationale=(
            "Mirror of major ransomware-group leak posts (Lockbit, "
            "ALPHV/BlackCat, Cl0p, RansomHub, Akira). Faster than the "
            "DLS scrapers because affiliates often crosspost here "
            "first."
        ),
    ),
    CuratedChannel(
        handle="alphv_repost",
        cluster="ransomware-leak",
        language="en",
        rationale=(
            "ALPHV / BlackCat affiliate reposter — channel persisted "
            "after the FBI takedown of their leak site, useful for "
            "tracking spinoff brands."
        ),
        status="defunct",
    ),
]


# ── Public surface ──────────────────────────────────────────────────


def list_curated_channels() -> list[CuratedChannel]:
    """Every curated channel across all clusters, active or not."""
    return list(_IRANIAN) + list(_ARABIC) + list(_RANSOMWARE)


def list_iranian_channels() -> list[CuratedChannel]:
    return list(_IRANIAN)


def list_arabic_channels() -> list[CuratedChannel]:
    return list(_ARABIC)


def list_hacktivist_channels() -> list[CuratedChannel]:
    return [c for c in list_curated_channels()
            if c.cluster in {"iranian-apt", "arabic-hacktivist"}]


def list_active_channels() -> list[CuratedChannel]:
    return [c for c in list_curated_channels() if c.status == "active"]
