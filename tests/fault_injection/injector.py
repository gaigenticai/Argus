"""In-process fault injector.

The injector exposes a small set of patches that any test can stack
inside a ``with FaultInjector(...)`` block. Each patch targets a
specific transport boundary:

    http_timeout(host)            aiohttp / httpx GETs to ``host``
                                  raise ``asyncio.TimeoutError``
    http_status(host, code)       same target returns the given HTTP
                                  status with empty body
    http_drop(host)               same target raises
                                  ``aiohttp.ClientConnectorError``
    smtp_failure(...)             smtplib.SMTP / SMTP_SSL raise
    redis_unavailable()           src.core.rate_limit._get_redis returns
                                  ``None`` and rds.set / rds.delete
                                  raise on an existing client
    db_pool_exhausted()           SQLAlchemy AsyncEngine.connect raises
                                  ``QueuePool limit of size N overflow N
                                  reached``
    minio_500()                   evidence_store.put / get raise
                                  ``ClientError`` with HTTP 500 body

All patches are reversed on context-manager exit. Tests can compose
multiple patches by nesting ``with`` blocks or by calling
``injector.activate(name, **kwargs)`` directly. Example::

    async def test_evidence_upload_handles_minio_500():
        with FaultInjector() as fi:
            fi.minio_500()
            with pytest.raises(HTTPException) as exc:
                await upload_evidence(...)
            assert exc.value.status_code == 503
"""

from __future__ import annotations

import asyncio
import contextlib
import smtplib
from typing import Any, Callable
from unittest import mock


class FaultInjector:
    """Stackable fault-injection context.

    The injector keeps a list of "active" patches and reverses them on
    exit. Each ``activate`` call pushes one patch onto the stack;
    ``deactivate`` (or context exit) pops them in reverse order.
    """

    def __init__(self) -> None:
        self._stack: list[contextlib.AbstractContextManager] = []

    def __enter__(self) -> "FaultInjector":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for ctx in reversed(self._stack):
            try:
                ctx.__exit__(exc_type, exc, tb)
            except Exception:  # noqa: BLE001 — teardown must not throw
                pass
        self._stack.clear()

    # --- HTTP ---------------------------------------------------------

    def http_timeout(self, host_substring: str) -> None:
        """Make any aiohttp GET to a URL containing ``host_substring``
        raise ``asyncio.TimeoutError``. Useful for feed-pull tests."""
        original = _get_aiohttp_session_get()

        async def fake_get(self, url, **kwargs):  # noqa: ARG001
            if host_substring in str(url):
                raise asyncio.TimeoutError(
                    f"FaultInjector: timeout for {url}"
                )
            return await original(self, url, **kwargs)

        ctx = mock.patch("aiohttp.ClientSession.get", new=fake_get)
        ctx.__enter__()
        self._stack.append(ctx)

    def http_status(self, host_substring: str, status: int = 503) -> None:
        """Make any aiohttp GET to ``host_substring`` return a synthetic
        response with ``status`` and an empty body."""
        ctx = _PatchAiohttpStatus(host_substring, status)
        ctx.__enter__()
        self._stack.append(ctx)

    def http_drop(self, host_substring: str) -> None:
        """Make any aiohttp GET to ``host_substring`` raise a connection-
        refused-style ClientConnectorError (the upstream is down)."""
        import aiohttp

        original = _get_aiohttp_session_get()

        async def fake_get(self, url, **kwargs):  # noqa: ARG001
            if host_substring in str(url):
                raise aiohttp.ClientConnectorError(
                    connection_key=mock.MagicMock(),
                    os_error=ConnectionRefusedError(
                        f"FaultInjector: drop for {url}"
                    ),
                )
            return await original(self, url, **kwargs)

        ctx = mock.patch("aiohttp.ClientSession.get", new=fake_get)
        ctx.__enter__()
        self._stack.append(ctx)

    # --- SMTP ---------------------------------------------------------

    def smtp_failure(self, exc: Exception | None = None) -> None:
        """Make smtplib.SMTP / SMTP_SSL raise on connect or on send.
        Used by takedown adapter resilience tests."""
        err = exc or smtplib.SMTPConnectError(421, b"FaultInjector: SMTP refused")

        def raising(*args, **kwargs):  # noqa: ARG001
            raise err

        ctx_a = mock.patch("smtplib.SMTP", side_effect=raising)
        ctx_a.__enter__()
        ctx_b = mock.patch("smtplib.SMTP_SSL", side_effect=raising)
        ctx_b.__enter__()
        self._stack.extend([ctx_a, ctx_b])

    # --- Redis --------------------------------------------------------

    def redis_unavailable(self) -> None:
        """Force ``src.core.rate_limit._get_redis`` to return None so
        every Redis-dependent path falls back to its degraded branch."""
        async def returning_none() -> None:
            return None

        ctx = mock.patch(
            "src.core.rate_limit._get_redis", new=returning_none,
        )
        ctx.__enter__()
        self._stack.append(ctx)

    def redis_raises(self, exc: Exception | None = None) -> None:
        """Force the existing Redis client's ``set`` / ``delete`` /
        ``get`` to raise. Tests connection-not-falling-out behaviour."""
        err = exc or ConnectionError("FaultInjector: redis crashed mid-op")

        async def raising(*args, **kwargs):  # noqa: ARG001
            raise err

        async def stub_get_redis():
            client = mock.AsyncMock()
            client.set = raising
            client.get = raising
            client.delete = raising
            return client

        ctx = mock.patch(
            "src.core.rate_limit._get_redis", new=stub_get_redis,
        )
        ctx.__enter__()
        self._stack.append(ctx)

    # --- DB -----------------------------------------------------------

    def db_pool_exhausted(self) -> None:
        """Make ``async_session_factory`` raise the SQLAlchemy
        QueuePool-overflow error every time. Tests health endpoints +
        worker shutdown behaviour."""
        from sqlalchemy.exc import TimeoutError as SAQueueTimeout

        def raising(*args, **kwargs):  # noqa: ARG001
            raise SAQueueTimeout(
                "FaultInjector: QueuePool limit of size 5 overflow 10 reached, "
                "connection timed out, timeout 30",
            )

        ctx = mock.patch(
            "src.storage.database.async_session_factory",
            side_effect=raising,
        )
        ctx.__enter__()
        self._stack.append(ctx)

    # --- MinIO --------------------------------------------------------

    def minio_500(self) -> None:
        """Make every evidence_store call raise a botocore ClientError
        with HTTP 500 body. Tests evidence upload / download error
        handling."""
        from botocore.exceptions import ClientError

        err = ClientError(
            error_response={
                "Error": {"Code": "500", "Message": "FaultInjector: minio down"},
                "ResponseMetadata": {"HTTPStatusCode": 500},
            },
            operation_name="PutObject",
        )

        def raising(*args, **kwargs):  # noqa: ARG001
            raise err

        names = (
            "src.storage.evidence_store.put",
            "src.storage.evidence_store.get",
            "src.storage.evidence_store.delete",
            "src.storage.evidence_store.exists",
        )
        for name in names:
            ctx = mock.patch(name, side_effect=raising)
            ctx.__enter__()
            self._stack.append(ctx)

    def minio_bucket_missing(self) -> None:
        """Make ``ensure_bucket`` raise NoSuchBucket; tests upload retry
        path / tenant bootstrap error surfacing."""
        from botocore.exceptions import ClientError

        err = ClientError(
            error_response={
                "Error": {"Code": "NoSuchBucket", "Message": "no bucket"},
                "ResponseMetadata": {"HTTPStatusCode": 404},
            },
            operation_name="HeadBucket",
        )

        def raising(*args, **kwargs):  # noqa: ARG001
            raise err

        ctx = mock.patch(
            "src.storage.evidence_store.ensure_bucket",
            side_effect=raising,
        )
        ctx.__enter__()
        self._stack.append(ctx)


# --- helpers ---------------------------------------------------------


def _get_aiohttp_session_get() -> Callable[..., Any]:
    """Resolve the un-patched aiohttp.ClientSession.get for delegation."""
    import aiohttp

    return aiohttp.ClientSession.get


class _PatchAiohttpStatus:
    """Context manager that swaps aiohttp.ClientSession.get with a
    function returning a pre-baked status code for matching URLs."""

    def __init__(self, host_substring: str, status: int) -> None:
        self.host_substring = host_substring
        self.status = status
        self._patcher: mock._patch | None = None

    def __enter__(self):
        original = _get_aiohttp_session_get()
        host = self.host_substring
        status = self.status

        async def fake_get(self, url, **kwargs):  # noqa: ARG001
            if host not in str(url):
                return await original(self, url, **kwargs)
            return _SyntheticResponse(status)

        self._patcher = mock.patch("aiohttp.ClientSession.get", new=fake_get)
        self._patcher.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._patcher is not None:
            self._patcher.__exit__(exc_type, exc, tb)


class _SyntheticResponse:
    """Minimal aiohttp.ClientResponse stand-in for fault tests."""

    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return ""

    async def json(self) -> dict:
        return {}

    async def read(self) -> bytes:
        return b""

    async def __aiter__(self):
        return
        yield  # pragma: no cover


__all__ = ["FaultInjector"]
