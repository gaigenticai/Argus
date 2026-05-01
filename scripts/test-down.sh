#!/usr/bin/env bash
# Tear down Argus test infrastructure cleanly.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose -p argus -f docker-compose.test.yml down -v
echo "✓ argus test infra removed"
