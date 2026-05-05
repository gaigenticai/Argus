"""Spamhaus DROP (Don't Route Or Peer) feed.

The DROP list is Spamhaus's hand-curated catalogue of netblocks that
should never be routed: hijacked space, spammer-controlled allocations,
and ranges associated with confirmed cybercrime operations. It's the
gold-standard "don't let traffic to/from these networks anywhere near
my infrastructure" feed and it's free to use under fair-use terms
(no key required).

In April 2024 Spamhaus merged eDROP (extended DROP) into DROP — the
``edrop.txt`` file is now empty and we don't fetch it; everything that
used to live there is in the unified ``drop.txt``.

Format:

    ; Spamhaus DROP List 2026/04/24 - (c) 2026 The Spamhaus Project SLU
    1.10.16.0/20 ; SBL256894
    1.19.0.0/16 ; SBL387990
    ...

Lines beginning with ``;`` are comments / metadata. Data lines are
``<CIDR> ; <SBL-ref>`` — we keep the SBL reference in feed_metadata
so analysts can pivot to spamhaus.org/sbl/<id> for context.

Spamhaus's terms of service cap automated downloads at "no more than
once per hour"; the 1h scheduler interval matches that ceiling.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"


class SpamhausDropFeed(BaseFeed):
    """Spamhaus DROP — hijacked + cybercrime netblocks."""

    name = "spamhaus_drop"
    layer = "ip_reputation"
    default_interval_seconds = 3600  # Spamhaus ToS: at most once per hour

    async def poll(self) -> AsyncIterator[FeedEntry]:
        lines = await self._fetch_csv_lines(_DROP_URL, skip_comments=False)
        if not lines:
            self.last_failure_reason = "Spamhaus DROP returned no data"
            return

        count = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Format: "1.10.16.0/20 ; SBL256894" — keep the SBL ref
            # if present so analysts can pivot to the upstream record.
            cidr = line
            sbl = ""
            if ";" in line:
                cidr_part, _, comment = line.partition(";")
                cidr = cidr_part.strip()
                sbl = comment.strip()
            if "/" not in cidr:
                # Defensive: drop.txt should always have CIDR notation,
                # but skip anything that doesn't look like a network.
                continue

            yield FeedEntry(
                feed_name="spamhaus_drop",
                layer=self.layer,
                entry_type="cidr",
                value=cidr,
                label=f"Spamhaus DROP: {cidr}",
                description=(
                    f"Hijacked / cybercrime netblock per Spamhaus DROP."
                    + (f" Reference: {sbl}." if sbl else "")
                ),
                severity="high",
                confidence=0.95,
                ip_for_geo=None,
                country_code=None,
                latitude=None,
                longitude=None,
                feed_metadata={
                    "source": "spamhaus_drop",
                    "sbl_reference": sbl or None,
                    "sbl_url": (
                        f"https://www.spamhaus.org/sbl/query/{sbl}"
                        if sbl.startswith("SBL") else None
                    ),
                },
                first_seen=None,
                # DROP list rotates daily; 7d expiry = if a netblock
                # falls off the upstream list, our IOCs age out.
                expires_hours=168,
            )
            count += 1

        logger.info("[%s] yielded %d netblock(s)", self.name, count)
