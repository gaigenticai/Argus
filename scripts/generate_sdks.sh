#!/usr/bin/env bash
#
# Generate Argus client SDKs from the live OpenAPI 3.1 schema (P3 #3.4).
#
# Pre-requisites (operator's local env, not bundled in the runtime image):
#   pip install openapi-python-client                # Python SDK
#   npm i  -g  openapi-typescript-codegen            # TS / JS SDK
#
# Usage:
#   ARGUS_HOST=http://localhost:8002 scripts/generate_sdks.sh [py|ts|both]
#
# The generated SDKs land under sdks/python and sdks/typescript and are
# .gitignored — operators rebuild them per release. The schema itself is
# served at GET /openapi.json on every running Argus instance and is the
# source of truth.

set -euo pipefail

ARGUS_HOST=${ARGUS_HOST:-http://localhost:8002}
TARGET=${1:-both}

mkdir -p sdks
SCHEMA="$(mktemp -t argus-openapi.XXXXXX.json)"
trap 'rm -f "$SCHEMA"' EXIT

echo "Fetching OpenAPI 3.1 schema from $ARGUS_HOST/openapi.json …"
curl -fsSL "$ARGUS_HOST/openapi.json" -o "$SCHEMA"
echo "  → $(wc -c < "$SCHEMA") bytes"

if [[ "$TARGET" == "py" || "$TARGET" == "both" ]]; then
  if ! command -v openapi-python-client >/dev/null; then
    echo "ERROR: openapi-python-client not on PATH; install with:" >&2
    echo "  pipx install openapi-python-client" >&2
    exit 1
  fi
  rm -rf sdks/python
  openapi-python-client generate --path "$SCHEMA" --output-path sdks/python
  echo "  ✓ Python SDK at sdks/python"
fi

if [[ "$TARGET" == "ts" || "$TARGET" == "both" ]]; then
  if ! command -v openapi >/dev/null; then
    echo "ERROR: openapi-typescript-codegen not on PATH; install with:" >&2
    echo "  npm i -g openapi-typescript-codegen" >&2
    exit 1
  fi
  rm -rf sdks/typescript
  openapi --input "$SCHEMA" --output sdks/typescript --client fetch \
          --useOptions --indent 2
  echo "  ✓ TypeScript SDK at sdks/typescript"
fi

echo "Done."
