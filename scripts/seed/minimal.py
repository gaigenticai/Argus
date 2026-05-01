"""Minimal seed — system organisation + admin user.

This is what gets created on a fresh production-style deployment. No demo
orgs, no fake findings. Just enough so the operator can log in and start
configuring real assets, feeds, and notification channels.

Idempotent: re-running on an existing deployment is a no-op.
"""

from __future__ import annotations

import os

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from scripts.seed._common import logger, now
from src.core.auth import hash_password
from src.models.auth import User, UserRole
from src.models.threat import Organization


SYSTEM_ORG_NAME_DEFAULT = "Argus"
SYSTEM_ORG_SLUG_ENV = "ARGUS_SYSTEM_ORGANIZATION_SLUG"
ADMIN_EMAIL_ENV = "ARGUS_BOOTSTRAP_ADMIN_EMAIL"
ADMIN_PASSWORD_ENV = "ARGUS_BOOTSTRAP_ADMIN_PASSWORD"


async def _ensure_system_org(session: AsyncSession) -> Organization:
    """Create the singleton system org if missing.

    The slug derives from ``ARGUS_SYSTEM_ORGANIZATION_SLUG`` so existing
    deployments that pinned a slug stay stable across re-seeds.
    """
    slug = os.environ.get(SYSTEM_ORG_SLUG_ENV) or "argus"
    existing = (
        await session.execute(
            select(Organization).where(Organization.name == SYSTEM_ORG_NAME_DEFAULT)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    org = Organization(
        name=SYSTEM_ORG_NAME_DEFAULT,
        domains=[],
        keywords=[],
        industry="Other",
    )
    session.add(org)
    await session.flush()
    logger.info(f"  · system org created (id={org.id}, slug={slug})")
    return org


async def _ensure_admin_user(session: AsyncSession) -> None:
    """Create an admin user if no users exist.

    Adversarial audit D-5 — the previous behaviour fell back to the
    literal ``"ChangeMe-On-First-Login!"`` when the operator forgot to
    set ARGUS_BOOTSTRAP_ADMIN_PASSWORD. That string lives in source
    control, so an attacker who reads the repo gets a working bootstrap
    credential. New behaviour: when the env var is unset, generate a
    cryptographically random password, print it ONCE to the seed log,
    and require the operator to capture it from the deployment log
    before any external traffic reaches /auth/login.
    """
    import secrets as _secrets

    has_user = (
        await session.execute(select(User.id).limit(1))
    ).scalar_one_or_none() is not None
    if has_user:
        return

    email = os.environ.get(ADMIN_EMAIL_ENV) or "admin@argus.local"
    env_password = os.environ.get(ADMIN_PASSWORD_ENV)
    generated = env_password is None
    if env_password:
        password = env_password
    else:
        # 24-char URL-safe token → 192 bits of entropy. Easy to copy
        # out of a deployment log; impossible to guess.
        password = _secrets.token_urlsafe(18)

    session.add(
        User(
            email=email,
            username=email.split("@", 1)[0],
            password_hash=hash_password(password),
            display_name="Administrator",
            role=UserRole.ADMIN.value,
            is_active=True,
        )
    )
    if generated:
        # Audit D-5 — the only place this random password is printed.
        # Make it loud enough that an operator can't miss it in a
        # `docker compose up` scrollback.
        logger.warning(
            "============================================================"
        )
        logger.warning(
            "BOOTSTRAP ADMIN — copy this password NOW (shown only once):"
        )
        logger.warning(f"  email:    {email}")
        logger.warning(f"  password: {password}")
        logger.warning(
            "Set %s in your environment to suppress this auto-generated default.",
            ADMIN_PASSWORD_ENV,
        )
        logger.warning(
            "============================================================"
        )
    else:
        logger.info(f"  · bootstrap admin: {email} (password from env)")


async def run(session_factory: async_sessionmaker[AsyncSession]) -> int:
    async with session_factory() as session:
        await _ensure_system_org(session)
        await _ensure_admin_user(session)
        await session.commit()
    logger.info("minimal seed complete")
    return 0
