"""Worker liveness check (Audit F4).

Exit 0 if the heartbeat file exists and is fresh (< MAX_AGE seconds
old). Exit 1 otherwise. Compose / k8s call this from a HEALTHCHECK
directive, which lets orchestrators restart a wedged worker.

Usage::

    python -m src.workers.healthcheck

Tunables:
    ARGUS_WORKER_HEARTBEAT      path to the heartbeat file (default /tmp/argus-worker.heartbeat)
    ARGUS_WORKER_HEARTBEAT_MAX_AGE  seconds (default 600 — twice the SLA tick)
"""

from __future__ import annotations

import os
import sys
import time


def main() -> int:
    path = os.environ.get("ARGUS_WORKER_HEARTBEAT", "/tmp/argus-worker.heartbeat")
    try:
        max_age = int(os.environ.get("ARGUS_WORKER_HEARTBEAT_MAX_AGE", "600"))
    except ValueError:
        max_age = 600

    try:
        with open(path) as f:
            ts = int(f.read().strip())
    except (OSError, ValueError) as e:
        print(f"unhealthy: cannot read heartbeat at {path}: {e}", file=sys.stderr)
        return 1

    age = int(time.time()) - ts
    if age > max_age:
        print(
            f"unhealthy: heartbeat {age}s old (limit {max_age}s)",
            file=sys.stderr,
        )
        return 1
    print(f"ok: heartbeat {age}s old")
    return 0


if __name__ == "__main__":
    sys.exit(main())
