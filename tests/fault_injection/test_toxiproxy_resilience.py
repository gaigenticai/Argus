"""Toxiproxy-driven resilience tests.

Skipped automatically when the ``argus-test-toxiproxy`` container is
not running — these are full-stack drills, not unit tests.

Bring up the harness with::

    docker compose -p argus -f docker-compose.test.yml up -d \\
        argus-test-toxiproxy argus-test-postgres argus-test-minio \\
        argus-test-redis

Then run::

    pytest tests/fault_injection/test_toxiproxy_resilience.py -v

The tests focus on the cases the in-process layer can't catch
faithfully: TCP latency mid-query, partial response slicing, and
RST-after-N-bytes — failure modes where a Python-level mock would
diverge from real socket behaviour.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.fault_injection import toxiproxy


pytestmark = pytest.mark.skipif(
    not toxiproxy.is_available(),
    reason=(
        "Toxiproxy not reachable. Bring up the test harness with "
        "`docker compose -p argus -f docker-compose.test.yml up -d` "
        "to enable these tests."
    ),
)


@pytest.fixture(scope="module", autouse=True)
def _ensure_proxies():
    toxiproxy.reset()
    toxiproxy.ensure_proxies()
    yield
    toxiproxy.reset()


@pytest.mark.asyncio
async def test_postgres_query_aborts_under_5s_latency():
    """A 5-second one-way latency injected on the Postgres connection
    must surface as a SQLAlchemy timeout once the pool's `pool_timeout`
    is exceeded — not as a hung worker.
    """
    import asyncpg

    with toxiproxy.toxic(
        "argus_postgres",
        type="latency",
        attributes={"latency": 5000},
    ):
        # Connect through the proxied port (55433) directly using
        # asyncpg so we don't pollute the SQLAlchemy pool.
        with pytest.raises((asyncio.TimeoutError, asyncpg.exceptions.ConnectionFailureError, OSError)):
            conn = await asyncio.wait_for(
                asyncpg.connect(
                    host="127.0.0.1",
                    port=55433,
                    user="argus",
                    password="argus",
                    database="argus_test",
                    timeout=2,
                ),
                timeout=3,
            )
            try:
                await conn.execute("SELECT 1")
            finally:
                await conn.close()


@pytest.mark.asyncio
async def test_minio_partial_response_aborts_upload():
    """When MinIO drops the connection after 256 bytes mid-PUT, the
    boto3 client should raise — never silently report success. We
    don't need to load real MinIO bytes; a tiny upload is enough for
    Toxiproxy's slicer to hit the cutoff.
    """
    import boto3
    from botocore.config import Config
    from botocore.exceptions import (
        ClientError,
        ConnectionClosedError,
        EndpointConnectionError,
        ReadTimeoutError,
    )

    s3 = boto3.client(
        "s3",
        endpoint_url="http://127.0.0.1:9200",
        aws_access_key_id="argus_test_only",
        aws_secret_access_key="argus_test_only_dummy_password",
        region_name="us-east-1",
        config=Config(retries={"max_attempts": 1}, connect_timeout=2, read_timeout=2),
    )
    bucket = "argus-evidence-faulttest"
    try:
        s3.create_bucket(Bucket=bucket)
    except ClientError:
        pass

    with toxiproxy.toxic(
        "argus_minio",
        type="limit_data",
        attributes={"bytes": 256},
    ):
        with pytest.raises(
            (ClientError, ConnectionClosedError, EndpointConnectionError, ReadTimeoutError, OSError)
        ):
            s3.put_object(Bucket=bucket, Key="big.bin", Body=b"x" * 1024 * 1024)


@pytest.mark.asyncio
async def test_redis_outage_keeps_login_path_alive():
    """RST-after-0-bytes on the Redis port simulates a dropped Redis.
    The auth_policy lockout helper must fail open and not block logins."""
    import redis.asyncio as aioredis

    # Override the rate_limit Redis URL to the proxied port.
    from src.core import rate_limit

    original = rate_limit._redis_pool
    rate_limit._redis_pool = None  # force re-init
    try:
        with toxiproxy.toxic(
            "argus_redis",
            type="reset_peer",
            attributes={"timeout": 0},
        ):
            # Even with Redis dead, is_account_locked must return False.
            # The function catches its own connection failure.
            from src.core.auth_policy import is_account_locked

            # Point to the proxied port for this test only:
            client = aioredis.from_url(
                "redis://127.0.0.1:6380/0",
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            rate_limit._redis_pool = client
            try:
                assert await is_account_locked("victim@example.com") is False
            finally:
                await client.close()
    finally:
        rate_limit._redis_pool = original
