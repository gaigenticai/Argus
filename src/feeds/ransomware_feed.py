"""Ransomware intelligence feed — polls ransomware.live API for victim disclosures and group activity."""

from __future__ import annotations


import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# Approximate geographic centroids for common ISO 3166-1 alpha-2 country codes.
# Used to place ransomware victims on the threat map when only a country code is available.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (39.8283, -98.5795),
    "GB": (55.3781, -3.4360),
    "CA": (56.1304, -106.3468),
    "DE": (51.1657, 10.4515),
    "FR": (46.6034, 1.8883),
    "IT": (41.8719, 12.5674),
    "ES": (40.4637, -3.7492),
    "AU": (-25.2744, 133.7751),
    "JP": (36.2048, 138.2529),
    "BR": (-14.2350, -51.9253),
    "IN": (20.5937, 78.9629),
    "CN": (35.8617, 104.1954),
    "RU": (61.5240, 105.3188),
    "KR": (35.9078, 127.7669),
    "MX": (23.6345, -102.5528),
    "NL": (52.1326, 5.2913),
    "BE": (50.5039, 4.4699),
    "SE": (60.1282, 18.6435),
    "NO": (60.4720, 8.4689),
    "DK": (56.2639, 9.5018),
    "FI": (61.9241, 25.7482),
    "CH": (46.8182, 8.2275),
    "AT": (47.5162, 14.5501),
    "PL": (51.9194, 19.1451),
    "PT": (39.3999, -8.2245),
    "IE": (53.1424, -7.6921),
    "CZ": (49.8175, 15.4730),
    "IL": (31.0461, 34.8516),
    "ZA": (-30.5595, 22.9375),
    "AR": (-38.4161, -63.6167),
    "CL": (-35.6751, -71.5430),
    "CO": (4.5709, -74.2973),
    "SG": (1.3521, 103.8198),
    "TW": (23.6978, 120.9605),
    "TH": (15.8700, 100.9925),
    "MY": (4.2105, 101.9758),
    "PH": (12.8797, 121.7740),
    "ID": (-0.7893, 113.9213),
    "TR": (38.9637, 35.2433),
    "AE": (23.4241, 53.8478),
    "SA": (23.8859, 45.0792),
    "EG": (26.8206, 30.8025),
    "NG": (9.0820, 8.6753),
    "KE": (-0.0236, 37.9062),
    "NZ": (-40.9006, 174.8860),
    "UA": (48.3794, 31.1656),
    "RO": (45.9432, 24.9668),
    "HU": (47.1625, 19.5033),
    "GR": (39.0742, 21.8243),
    "HR": (45.1000, 15.2000),
    "SK": (48.6690, 19.6990),
    "BG": (42.7339, 25.4858),
    "LT": (55.1694, 23.8813),
    "LV": (56.8796, 24.6032),
    "EE": (58.5953, 25.0136),
    "PE": (-9.1900, -75.0152),
    "VE": (6.4238, -66.5897),
    "PK": (30.3753, 69.3451),
    "BD": (23.6850, 90.3563),
    "VN": (14.0583, 108.2772),
}


class RansomwareFeed(BaseFeed):
    """Polls ransomware.live API for recent victim disclosures and active group intelligence."""

    name = "ransomware_live"
    layer = "ransomware"
    default_interval_seconds = 21600  # 6 hours

    VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"
    GROUPS_URL = "https://api.ransomware.live/v2/groups"

    async def poll(self) -> AsyncIterator[FeedEntry]:
        """Yield victim entries from ransomware.live, then active group summaries."""
        seen_victims: set[str] = set()

        # ── Recent victims ──────────────────────────────────────────────
        victims = await self._fetch_json(self.VICTIMS_URL)
        if isinstance(victims, list):
            logger.info("[%s] Fetched %d recent victims", self.name, len(victims))
            for v in victims:
                victim_name = (v.get("victim") or "").strip()
                group_name = (v.get("group") or "unknown").strip()
                if not victim_name:
                    continue

                dedup_key = f"{group_name}|{victim_name}"
                if dedup_key in seen_victims:
                    continue
                seen_victims.add(dedup_key)

                country = (v.get("country") or "").strip().upper()
                sector = (v.get("sector") or "").strip()
                discovery_date = (v.get("date") or "").strip()
                leak_url = (v.get("url") or "").strip()

                lat, lon = COUNTRY_CENTROIDS.get(country, (None, None))

                # Parse discovery date if available
                first_seen = None
                if discovery_date:
                    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
                        try:
                            first_seen = datetime.strptime(discovery_date, fmt).replace(
                                tzinfo=timezone.utc
                            )
                            break
                        except ValueError:
                            continue

                desc_parts = [f"Ransomware group '{group_name}' claimed victim '{victim_name}'"]
                if sector:
                    desc_parts.append(f"sector: {sector}")
                if discovery_date:
                    desc_parts.append(f"disclosed: {discovery_date}")
                if leak_url:
                    desc_parts.append(f"leak site: {leak_url}")
                description = " | ".join(desc_parts)

                # GCC relevance scoring (P1 #1.5) — adds gcc_relevance
                # block to feed_metadata so dashboards / alert pipelines
                # can filter to the regional subset without re-scoring.
                from src.intel.gcc_ransomware_filter import score_gcc_relevance
                gcc = score_gcc_relevance(
                    victim_name=victim_name,
                    country=country,
                    url=leak_url,
                    sector=sector,
                    group=group_name,
                    description=description,
                )

                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type="victim",
                    value=victim_name,
                    label=(
                        f"[GCC] {group_name}: {victim_name}"
                        if gcc.is_gcc
                        else f"{group_name}: {victim_name}"
                    ),
                    description=description,
                    severity="critical",
                    confidence=0.9,
                    country_code=country if country else None,
                    latitude=lat,
                    longitude=lon,
                    feed_metadata={
                        "group": group_name,
                        "sector": sector or None,
                        "discovery_date": discovery_date or None,
                        "leak_url": leak_url or None,
                        "source": "ransomware_live_victims",
                        "gcc_relevance": gcc.to_dict(),
                    },
                    first_seen=first_seen,
                    expires_hours=720,  # 30 days — ransomware victims stay relevant
                )
        else:
            logger.warning("[%s] Failed to fetch recent victims or unexpected format", self.name)

        # ── Active ransomware groups ────────────────────────────────────
        groups = await self._fetch_json(self.GROUPS_URL)
        if isinstance(groups, list):
            logger.info("[%s] Fetched %d ransomware groups", self.name, len(groups))
            for g in groups:
                group_name = (g.get("name") or "").strip()
                if not group_name:
                    continue

                # Extract useful group metadata
                locations_count = 0
                urls = g.get("locations") or g.get("urls") or []
                if isinstance(urls, list):
                    locations_count = len(urls)

                profile = (g.get("profile") or "").strip()
                last_seen = (g.get("last_seen") or "").strip()

                description = f"Active ransomware group: {group_name}"
                if profile:
                    # Truncate long profiles
                    description += f" — {profile[:300]}"
                if last_seen:
                    description += f" | last active: {last_seen}"

                first_seen_dt = None
                if last_seen:
                    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
                        try:
                            first_seen_dt = datetime.strptime(last_seen, fmt).replace(
                                tzinfo=timezone.utc
                            )
                            break
                        except ValueError:
                            continue

                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type="victim",
                    value=group_name,
                    label=f"Group: {group_name}",
                    description=description,
                    severity="high",
                    confidence=0.85,
                    feed_metadata={
                        "is_group_entry": True,
                        "group": group_name,
                        "profile": profile or None,
                        "leak_site_count": locations_count,
                        "last_seen": last_seen or None,
                        "source": "ransomware_live_groups",
                    },
                    first_seen=first_seen_dt,
                    expires_hours=720,
                )
        else:
            logger.warning("[%s] Failed to fetch groups or unexpected format", self.name)
