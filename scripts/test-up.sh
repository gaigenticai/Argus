#!/usr/bin/env bash
# Bring up Argus test infrastructure under Docker Compose project "argus".
# Containers appear nested under "argus" in Docker Desktop, matching
# the gaigenticos layout. Idempotent.

set -euo pipefail

cd "$(dirname "$0")/.."

docker compose -p argus -f docker-compose.test.yml up -d

echo "Waiting for postgres..."
until docker exec argus-test-postgres pg_isready -U argus >/dev/null 2>&1; do sleep 1; done

echo "Waiting for minio..."
until curl -sf http://127.0.0.1:9100/minio/health/live >/dev/null 2>&1; do sleep 1; done

echo "✓ argus test infra ready (postgres :55432, minio :9100)"
echo "  exporting env: source scripts/test-env.sh"
