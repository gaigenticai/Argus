"""Export the live FastAPI OpenAPI 3.1 schema to a versioned file.

The schema served at GET /openapi.json on a running Argus instance is
the source of truth, but customers building SDKs and CI pipelines
expect a checked-in file they can vendor without spinning up the
backend. This script writes that file to:

  clients/openapi/argus.openapi.json

Usage:
  ARGUS_BACKEND_URL=http://localhost:8002 \\
      python scripts/export_openapi.py

  # Or, no live server — generate from the FastAPI app object directly:
  python scripts/export_openapi.py --offline

The offline mode imports ``src.api.app`` and calls ``app.openapi()``
without binding a port; useful in CI where there's no running server.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.request import urlopen


_OUT = Path(__file__).resolve().parent.parent / "clients" / "openapi" / "argus.openapi.json"


def _via_live(url: str) -> dict:
    with urlopen(url) as resp:    # noqa: S310 — operator-supplied URL
        return json.load(resp)


def _via_offline() -> dict:
    # Set safe defaults so importing the app object doesn't blow up
    # outside of a live deployment.
    os.environ.setdefault(
        "ARGUS_JWT_SECRET", "x" * 64,
    )
    os.environ.setdefault(
        "DATABASE_URL", "postgresql+asyncpg://argus:argus@localhost/argus",
    )
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.api.app import app
    return app.openapi()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--offline", action="store_true",
        help="Build schema from src.api.app without a live server.",
    )
    ap.add_argument(
        "--url", default=os.environ.get(
            "ARGUS_BACKEND_URL", "http://localhost:8002",
        ) + "/openapi.json",
        help="Live /openapi.json URL (default ARGUS_BACKEND_URL/openapi.json).",
    )
    ap.add_argument(
        "--out", default=str(_OUT),
        help="Output path (default clients/openapi/argus.openapi.json).",
    )
    args = ap.parse_args()

    schema = _via_offline() if args.offline else _via_live(args.url)

    if schema.get("openapi", "").split(".")[0] != "3":
        print(f"unexpected openapi version: {schema.get('openapi')!r}",
              file=sys.stderr)
        return 1
    paths = len(schema.get("paths") or {})
    components = len((schema.get("components") or {}).get("schemas") or {})

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
    )
    print(f"wrote {out_path} — {paths} paths · {components} schemas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
