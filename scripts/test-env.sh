# Source this file (do not exec) to export the env vars needed for
# `pytest tests/` to find the test postgres + minio brought up by
# scripts/test-up.sh.
#
# Usage:  source scripts/test-env.sh

export ARGUS_TEST_DB_URL="postgresql+asyncpg://argus:argus@localhost:55432/argus_test"
export ARGUS_DB_HOST=localhost
export ARGUS_DB_PORT=55432
export ARGUS_DB_NAME=argus_test
export ARGUS_DB_USER=argus
export ARGUS_DB_PASSWORD=argus
export ARGUS_TEST_MINIO_URL="http://localhost:9100"
export ARGUS_EVIDENCE_ENDPOINT_URL="http://localhost:9100"
export ARGUS_EVIDENCE_ACCESS_KEY=argus_test_only
export ARGUS_EVIDENCE_SECRET_KEY=argus_test_only_dummy_password
export ARGUS_JWT_SECRET="${ARGUS_JWT_SECRET:-dev-secret-do-not-use-in-prod-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"
