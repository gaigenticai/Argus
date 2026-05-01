"""Seed dispatcher.

Reads ``ARGUS_SEED_MODE`` (or ``--mode`` flag) and runs the matching
variant. Exit code is 0 on success or no-op, non-zero on hard failure.

The compose ``argus-seed`` one-shot service runs ``python -m scripts.seed``
on startup. Setting ``ARGUS_SEED_MODE=none`` (or any unknown value) makes
this a fast no-op so production deployments aren't surprised by demo rows.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from scripts.seed._common import logger


VALID_MODES = {"none", "minimal", "realistic", "stress"}


def _parse() -> tuple[str, bool]:
    parser = argparse.ArgumentParser(prog="scripts.seed")
    parser.add_argument(
        "--mode",
        default=None,
        help="Seed mode (none|minimal|realistic|stress). Overrides ARGUS_SEED_MODE.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe demo orgs before seeding (realistic/stress only).",
    )
    args = parser.parse_args()
    mode = (args.mode or os.environ.get("ARGUS_SEED_MODE") or "minimal").strip().lower()
    return mode, args.reset


async def _run(mode: str, reset: bool) -> int:
    if mode == "none":
        logger.info("ARGUS_SEED_MODE=none — skipping seed entirely")
        return 0

    if mode not in VALID_MODES:
        logger.error(
            f"unknown ARGUS_SEED_MODE={mode!r}; expected one of {sorted(VALID_MODES)}"
        )
        return 2

    # init schema before anything else; seed runs on a freshly-migrated DB
    from src.storage import database as _db

    await _db.init_db()
    if _db.async_session_factory is None:
        logger.error("init_db() did not populate the session factory")
        return 1

    if mode == "minimal":
        from scripts.seed.minimal import run as run_minimal

        return await run_minimal(_db.async_session_factory)

    # realistic/stress share the same loader; stress dials cardinality up
    from scripts.seed.realistic import run as run_realistic

    return await run_realistic(_db.async_session_factory, reset=reset, stress=mode == "stress")


def main() -> None:
    mode, reset = _parse()
    logger.info(f"=== Argus seed: mode={mode} reset={reset} ===")
    rc = asyncio.run(_run(mode, reset))
    if rc == 0:
        logger.info("=== Done ===")
    sys.exit(rc)


if __name__ == "__main__":
    main()
