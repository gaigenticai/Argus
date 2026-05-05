"""FireHOL aggregated IP-list feed.

FireHOL (https://iplists.firehol.org) curates ~400 public IP blocklists
into a small number of pre-aggregated, deduplicated tiers:

  * **firehol_level1** — conservative; the safest default for any
    edge device. Includes dshield, feodo, fullbogons, spamhaus_drop.
    ~3,750 subnets / ~611M unique IPs at the time of writing.
  * **firehol_level2** — adds short-lived attack data (recent
    SSH/HTTP brute-forcers).
  * **firehol_level3** — most aggressive; includes longer attack
    history. Higher false-positive risk.

We default to **level1** because Argus is a SOC/intel platform — false
positives waste analyst time. Operators who want broader coverage can
switch via ``ARGUS_FEED_FIREHOL_URL`` (e.g. point at
firehol_level3.netset).

Format: plain text, one CIDR per line; lines starting with ``#`` are
comments + metadata. We persist each CIDR as a FeedEntry with
``entry_type="cidr"`` and surface the source level in feed_metadata
so an analyst can tell "this hit came from level1 vs level3".

Update frequency: FireHOL refreshes most lists every 1-30 minutes.
We poll once per hour — the bulk of attack-surface IPs we care about
don't change in shorter windows, and hourly avoids hammering the
upstream.
"""

from __future__ import annotations

import logging
import os
from typing import AsyncIterator
from urllib.parse import urlparse

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


_DEFAULT_URL = "https://iplists.firehol.org/files/firehol_level1.netset"


class FireHOLFeed(BaseFeed):
    """FireHOL aggregated IP blocklist (level1 by default)."""

    name = "firehol"
    layer = "ip_reputation"
    default_interval_seconds = 3600  # 1h

    def _resolve_url(self) -> str:
        return (
            os.environ.get("ARGUS_FEED_FIREHOL_URL") or _DEFAULT_URL
        ).strip()

    @staticmethod
    def _list_label_from_url(url: str) -> str:
        """Extract the FireHOL list short-name from the URL — e.g.
        ``firehol_level1`` from ``.../firehol_level1.netset``. We
        surface this on every FeedEntry so the dashboard can sort/
        filter by aggressiveness."""
        path = urlparse(url).path
        leaf = (path.rsplit("/", 1)[-1] if path else "firehol")
        return leaf.rsplit(".", 1)[0] or "firehol"

    async def poll(self) -> AsyncIterator[FeedEntry]:
        url = self._resolve_url()
        list_label = self._list_label_from_url(url)
        lines = await self._fetch_csv_lines(url, skip_comments=False)
        if not lines:
            self.last_failure_reason = f"FireHOL list at {url} returned no data"
            return

        count = 0
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            cidr = line.split()[0]  # any inline whitespace = treat as separator
            if "/" not in cidr:
                # Bare IPv4 in some lists — normalise to /32.
                cidr = cidr + "/32"
            yield FeedEntry(
                feed_name="firehol",
                layer=self.layer,
                entry_type="cidr",
                value=cidr,
                label=f"FireHOL {list_label}: {cidr}",
                description=(
                    f"IP / netblock listed on FireHOL {list_label}. "
                    "FireHOL aggregates ~400 public blocklists; this row "
                    "appeared on the configured tier."
                ),
                # level1 is conservative → high confidence; if the operator
                # opts into level3 we keep severity high but don't bump it.
                severity="high",
                confidence=0.85,
                ip_for_geo=None,
                country_code=None,
                latitude=None,
                longitude=None,
                feed_metadata={
                    "source": "firehol",
                    "firehol_list": list_label,
                },
                first_seen=None,
                expires_hours=72,  # FireHOL rotates often; short TTL keeps stale rows out
            )
            count += 1

        logger.info("[%s] yielded %d CIDR(s) from %s", self.name, count, list_label)
