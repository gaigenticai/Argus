"""Self-healing maintenance jobs.

These run on the worker tick loop alongside the agentic and ingestion
ticks. Their job is to keep operator-curated data current without
manual intervention:

- ``refresh_ransomware_targets`` — pulls currently-active ransomware
  group .onion URLs from a public aggregator and updates the
  ``crawler_targets`` table. Marks rotated/dead URLs inactive.
- ``prune_dead_telegram_channels`` — probes each curated Telegram
  channel via the public web preview, marks 302-redirected handles as
  defunct in the ``crawler_targets`` table.

Without these, the dark-web data layer goes stale within a month —
ransomware groups rotate onion URLs every 2-3 weeks; Telegram bans
hacktivist channels constantly. A platform that doesn't auto-heal is
silently broken from the operator's POV.

Each maintenance job:
  - Writes a ``FeedHealth`` row keyed ``maintenance.<job_name>`` so
    the dashboard surfaces last-run status alongside the ingestion
    feeds.
  - Bounds its work (caps probes, respects timeouts) so a single tick
    can't stall the worker loop.
  - Is idempotent — re-running on the same DB state is a no-op.
"""

from __future__ import annotations

__all__ = [
    "refresh_ransomware_targets",
    "prune_dead_telegram_channels",
]
