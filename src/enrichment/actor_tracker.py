"""Threat actor identification, tracking, and risk scoring."""

from __future__ import annotations


import logging
import uuid as _uuid
from datetime import datetime, timezone

from sqlalchemy import select, func, or_, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel import IOC, ThreatActor, ActorSighting
from src.models.threat import Alert

logger = logging.getLogger(__name__)


async def identify_actor(
    username: str,
    platform: str,
    db: AsyncSession,
) -> ThreatActor | None:
    """Look up a threat actor by alias across all known actors.

    Checks both `primary_alias` and the `aliases` array column.
    Returns the first matching ThreatActor or None.
    """
    username_lower = username.lower().strip()
    if not username_lower:
        return None

    # Check primary_alias (case-insensitive)
    stmt = select(ThreatActor).where(
        func.lower(ThreatActor.primary_alias) == username_lower
    )
    result = await db.execute(stmt)
    actor = result.scalar_one_or_none()
    if actor:
        return actor

    # Check aliases array — PostgreSQL ANY() on ARRAY column
    stmt = select(ThreatActor).where(
        func.lower(func.unnest(ThreatActor.aliases)) == username_lower
    )
    # unnest approach doesn't work cleanly in a WHERE; use array contains instead
    # PostgreSQL: username = ANY(aliases) — case-insensitive via lower()
    stmt = select(ThreatActor).where(
        ThreatActor.aliases.any(username_lower)
    )
    result = await db.execute(stmt)
    actor = result.scalar_one_or_none()
    if actor:
        return actor

    # Also try original casing in the array
    if username_lower != username.strip():
        stmt = select(ThreatActor).where(
            ThreatActor.aliases.any(username.strip())
        )
        result = await db.execute(stmt)
        actor = result.scalar_one_or_none()
        if actor:
            return actor

    return None


async def create_or_update_actor(
    username: str,
    platform: str,
    raw_intel_id: _uuid.UUID,
    alert_id: _uuid.UUID | None,
    db: AsyncSession,
) -> ThreatActor:
    """Create a new threat actor or update an existing one.

    - If actor exists: increment sightings, update last_seen, add platform if new.
    - If not: create a new ThreatActor record.
    - Always creates an ActorSighting record.
    """
    now = datetime.now(timezone.utc)
    username_clean = username.strip()

    actor = await identify_actor(username_clean, platform, db)

    if actor:
        # Update existing actor
        actor.total_sightings += 1
        actor.last_seen = now
        actor.updated_at = now

        # Add platform to forums_active if not already there
        current_forums = actor.forums_active or []
        if platform not in current_forums:
            actor.forums_active = current_forums + [platform]

        # Add username as alias if it's different from primary and not already listed
        if username_clean.lower() != actor.primary_alias.lower():
            current_aliases = actor.aliases or []
            if username_clean not in current_aliases:
                actor.aliases = current_aliases + [username_clean]

        logger.info(
            "[actor_tracker] Updated actor %s (sightings=%d, platform=%s)",
            actor.primary_alias, actor.total_sightings, platform,
        )
    else:
        # Create new actor
        actor = ThreatActor(
            primary_alias=username_clean,
            aliases=[username_clean],
            forums_active=[platform],
            languages=[],
            pgp_fingerprints=[],
            known_ttps=[],
            risk_score=0.0,
            first_seen=now,
            last_seen=now,
            total_sightings=1,
        )
        db.add(actor)
        await db.flush()  # get the actor.id
        logger.info(
            "[actor_tracker] Created new actor %s on %s", username_clean, platform
        )

    # Record sighting
    sighting = ActorSighting(
        threat_actor_id=actor.id,
        raw_intel_id=raw_intel_id,
        alert_id=alert_id,
        source_platform=platform,
        alias_used=username_clean,
        context={"timestamp": now.isoformat()},
    )
    db.add(sighting)

    # Recalculate risk score
    actor.risk_score = await calculate_risk_score(actor, db)

    return actor


async def merge_actors(
    primary_id: _uuid.UUID,
    secondary_id: _uuid.UUID,
    db: AsyncSession,
) -> ThreatActor:
    """Merge two threat actors when confirmed as the same person.

    The secondary actor's data is folded into the primary. The secondary is deleted.
    - Aliases are combined (deduplicated).
    - Sightings are re-pointed.
    - IOCs are re-pointed.
    - Forums, languages, TTPs are merged.
    - Sighting counts are summed.
    - first_seen takes the earlier date; last_seen takes the later.
    """
    primary = await db.get(ThreatActor, primary_id)
    secondary = await db.get(ThreatActor, secondary_id)

    if not primary:
        raise ValueError(f"Primary actor {primary_id} not found")
    if not secondary:
        raise ValueError(f"Secondary actor {secondary_id} not found")
    if primary_id == secondary_id:
        raise ValueError("Cannot merge an actor with itself")

    # Merge aliases
    all_aliases = set(primary.aliases or [])
    all_aliases.add(secondary.primary_alias)
    all_aliases.update(secondary.aliases or [])
    primary.aliases = sorted(all_aliases)

    # Merge forums
    all_forums = set(primary.forums_active or [])
    all_forums.update(secondary.forums_active or [])
    primary.forums_active = sorted(all_forums)

    # Merge languages
    all_langs = set(primary.languages or [])
    all_langs.update(secondary.languages or [])
    primary.languages = sorted(all_langs)

    # Merge PGP fingerprints
    all_pgp = set(primary.pgp_fingerprints or [])
    all_pgp.update(secondary.pgp_fingerprints or [])
    primary.pgp_fingerprints = sorted(all_pgp)

    # Merge TTPs
    all_ttps = set(primary.known_ttps or [])
    all_ttps.update(secondary.known_ttps or [])
    primary.known_ttps = sorted(all_ttps)

    # Merge sighting counts
    primary.total_sightings += secondary.total_sightings

    # Date bounds
    if secondary.first_seen < primary.first_seen:
        primary.first_seen = secondary.first_seen
    if secondary.last_seen > primary.last_seen:
        primary.last_seen = secondary.last_seen

    # Merge profile data
    primary_profile = primary.profile_data or {}
    secondary_profile = secondary.profile_data or {}
    merged_profile = {**secondary_profile, **primary_profile}
    if secondary_profile:
        merged_profile["_merged_from"] = merged_profile.get("_merged_from", [])
        merged_profile["_merged_from"].append(str(secondary_id))
    primary.profile_data = merged_profile

    # Re-point all sightings from secondary → primary
    await db.execute(
        update(ActorSighting)
        .where(ActorSighting.threat_actor_id == secondary_id)
        .values(threat_actor_id=primary_id)
    )

    # Re-point all IOCs from secondary → primary
    await db.execute(
        update(IOC)
        .where(IOC.threat_actor_id == secondary_id)
        .values(threat_actor_id=primary_id)
    )

    # Delete secondary actor
    await db.delete(secondary)
    await db.flush()

    # Recalculate risk score
    primary.risk_score = await calculate_risk_score(primary, db)

    logger.info(
        "[actor_tracker] Merged actor %s into %s",
        secondary.primary_alias, primary.primary_alias,
    )

    return primary


async def calculate_risk_score(
    actor: ThreatActor,
    db: AsyncSession,
) -> float:
    """Compute risk score (0.0–100.0) based on multiple factors.

    Factors:
    1. Sighting volume (0–25 pts): log-scaled sighting count
    2. Alert severity (0–30 pts): weighted sum of linked alert severities
    3. Platform diversity (0–20 pts): number of distinct platforms
    4. Recency (0–15 pts): how recently active
    5. TTP breadth (0–10 pts): diversity of known techniques
    """
    import math

    score = 0.0

    # 1. Sighting volume — logarithmic scaling, caps at 25
    sighting_count = actor.total_sightings or 1
    sighting_score = min(25.0, math.log2(sighting_count + 1) * 5.0)
    score += sighting_score

    # 2. Alert severity — query linked alerts via sightings
    sighting_alert_ids = select(ActorSighting.alert_id).where(
        ActorSighting.threat_actor_id == actor.id,
        ActorSighting.alert_id.isnot(None),
    )
    alert_result = await db.execute(
        select(Alert.severity, func.count()).where(
            Alert.id.in_(sighting_alert_ids)
        ).group_by(Alert.severity)
    )
    severity_weights = {
        "critical": 10.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 2.0,
        "info": 0.5,
    }
    severity_score = 0.0
    for sev, cnt in alert_result:
        severity_score += severity_weights.get(sev, 1.0) * cnt
    score += min(30.0, severity_score)

    # 3. Platform diversity
    forums = actor.forums_active or []
    platform_score = min(20.0, len(forums) * 5.0)
    score += platform_score

    # 4. Recency — full score if active in last 7 days, decays over 90 days
    now = datetime.now(timezone.utc)
    if actor.last_seen:
        days_ago = (now - actor.last_seen).total_seconds() / 86400.0
        if days_ago <= 7:
            recency_score = 15.0
        elif days_ago <= 90:
            recency_score = 15.0 * (1.0 - (days_ago - 7) / 83.0)
        else:
            recency_score = 0.0
        score += max(0.0, recency_score)

    # 5. TTP breadth
    ttps = actor.known_ttps or []
    ttp_score = min(10.0, len(ttps) * 2.0)
    score += ttp_score

    return round(min(100.0, max(0.0, score)), 2)
