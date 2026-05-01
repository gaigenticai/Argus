"""Argus Python SDK — top-level client.

The client owns one ``httpx`` session and resource sub-clients hang off
of it (``client.alerts``, ``client.iocs``, …). Each sub-client takes
the parent and reuses its session so token / API-key state lives in one
place.

Authentication:
  - **API key** — ``ArgusClient(api_key="...")``. The SDK sends it as
    ``X-API-Key`` on every request.
  - **Username / password** — ``ArgusClient(...).login(email, pw)``.
    Calls ``POST /api/v1/auth/login`` and stores the access token.

Errors:
  - Any 4xx / 5xx response raises ``ArgusError`` with the parsed
    ``detail`` string (or the raw text if the body wasn't JSON).
"""

from __future__ import annotations

from typing import Any, Iterable

import httpx


class ArgusError(Exception):
    """Raised on any non-2xx HTTP response."""

    def __init__(self, status: int, detail: str, *, request_url: str = ""):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail
        self.request_url = request_url


# ── Sub-clients ─────────────────────────────────────────────────────


class _Alerts:
    def __init__(self, parent: "ArgusClient"):
        self._p = parent

    def list(
        self, *,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List alerts. Filters map to ``GET /api/v1/alerts``."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if category:
            params["category"] = category
        return self._p._get_json("/api/v1/alerts/", params=params)

    def get(self, alert_id: str) -> dict:
        return self._p._get_json(f"/api/v1/alerts/{alert_id}")


class _IOCs:
    def __init__(self, parent: "ArgusClient"):
        self._p = parent

    def list(
        self, *,
        ioc_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if ioc_type:
            params["ioc_type"] = ioc_type
        return self._p._get_json("/api/v1/iocs", params=params)


class _Feeds:
    def __init__(self, parent: "ArgusClient"):
        self._p = parent

    def list(self) -> list[dict]:
        return self._p._get_json("/api/v1/feeds")


class _Subscriptions:
    """Per-user feed subscriptions (P3 #3.4 final piece).

    A subscription is a saved filter expression + a delivery channel
    (webhook URL, email address, or in-app). Argus matches every newly
    created alert against every active subscription and dispatches.
    """

    def __init__(self, parent: "ArgusClient"):
        self._p = parent

    def list(self) -> list[dict]:
        return self._p._get_json("/api/v1/feed-subscriptions")

    def create(
        self,
        *,
        name: str,
        filter: dict[str, Any],
        channels: list[dict[str, Any]],
        active: bool = True,
    ) -> dict:
        body = {
            "name": name,
            "filter": filter,
            "channels": channels,
            "active": active,
        }
        return self._p._post_json("/api/v1/feed-subscriptions", body)

    def delete(self, subscription_id: str) -> None:
        self._p._delete(f"/api/v1/feed-subscriptions/{subscription_id}")


class _Intel:
    """Read access to /intel/* — sigma rules, yara, taxii, sandbox,
    breach providers, etc. Wraps the most common buyer endpoints."""

    def __init__(self, parent: "ArgusClient"):
        self._p = parent

    def sigma_backends(self) -> list[str]:
        out = self._p._get_json("/api/v1/intel/sigma/backends")
        if isinstance(out, dict) and "backends" in out:
            return list(out["backends"])
        return out  # type: ignore[return-value]

    def yara_availability(self) -> dict:
        return self._p._get_json("/api/v1/intel/yara/availability")

    def taxii_collections(self) -> dict:
        return self._p._get_json("/taxii2/collections/")

    def cves(
        self, *,
        cve_id: str | None = None,
        limit: int = 100,
    ) -> list[dict] | dict:
        if cve_id:
            return self._p._get_json(f"/api/v1/intel/cves/{cve_id}")
        return self._p._get_json("/api/v1/intel/cves", params={"limit": limit})


# ── Top-level client ───────────────────────────────────────────────


class ArgusClient:
    """Sync Argus client. Wraps an ``httpx.Client``.

    Typical usage::

        client = ArgusClient(base_url="https://argus.example",
                              api_key="argus_...")
        for a in client.alerts.list(severity="critical"):
            print(a["title"])
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        access_token: str | None = None,
        timeout: float = 30.0,
        verify: bool | str = True,
    ):
        self._base = base_url.rstrip("/")
        self._api_key = api_key or ""
        self._access_token = access_token or ""
        self._http = httpx.Client(
            base_url=self._base, timeout=timeout, verify=verify,
            follow_redirects=True,
        )
        self.alerts = _Alerts(self)
        self.iocs = _IOCs(self)
        self.feeds = _Feeds(self)
        self.subscriptions = _Subscriptions(self)
        self.intel = _Intel(self)

    # — auth —

    def login(self, email: str, password: str) -> "ArgusClient":
        """``POST /api/v1/auth/login`` and store the access token."""
        body = {"email": email, "password": password}
        out = self._post_json("/api/v1/auth/login", body, _auth_required=False)
        self._access_token = out.get("access_token") or ""
        if not self._access_token:
            raise ArgusError(500, "no access_token in login response")
        return self

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ArgusClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # — request plumbing —

    def _headers(self, *, auth_required: bool = True) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if auth_required:
            if self._access_token:
                h["Authorization"] = f"Bearer {self._access_token}"
            elif self._api_key:
                h["X-API-Key"] = self._api_key
        return h

    def _check(self, resp: httpx.Response) -> Any:
        if resp.status_code < 200 or resp.status_code >= 300:
            try:
                detail = resp.json().get("detail") or resp.text
            except ValueError:
                detail = resp.text
            raise ArgusError(
                resp.status_code, str(detail)[:500],
                request_url=str(resp.request.url),
            )
        if not resp.content:
            return None
        ctype = resp.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            return resp.json()
        return resp.text

    def _get_json(self, path: str, *, params: dict | None = None) -> Any:
        r = self._http.get(path, params=params, headers=self._headers())
        return self._check(r)

    def _post_json(
        self, path: str, body: Any, *, _auth_required: bool = True,
    ) -> Any:
        r = self._http.post(
            path, json=body,
            headers=self._headers(auth_required=_auth_required),
        )
        return self._check(r)

    def _delete(self, path: str) -> Any:
        r = self._http.delete(path, headers=self._headers())
        return self._check(r)


# ── Async mirror ────────────────────────────────────────────────────


class _AlertsAsync:
    def __init__(self, parent: "ArgusAsyncClient"):
        self._p = parent

    async def list(
        self, *,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if category:
            params["category"] = category
        return await self._p._get_json("/api/v1/alerts/", params=params)

    async def get(self, alert_id: str) -> dict:
        return await self._p._get_json(f"/api/v1/alerts/{alert_id}")


class _IOCsAsync:
    def __init__(self, parent: "ArgusAsyncClient"):
        self._p = parent

    async def list(self, **kw) -> list[dict]:
        params: dict[str, Any] = {"limit": kw.get("limit", 100),
                                    "offset": kw.get("offset", 0)}
        if kw.get("ioc_type"):
            params["ioc_type"] = kw["ioc_type"]
        return await self._p._get_json("/api/v1/iocs", params=params)


class _FeedsAsync:
    def __init__(self, parent: "ArgusAsyncClient"):
        self._p = parent

    async def list(self) -> list[dict]:
        return await self._p._get_json("/api/v1/feeds")


class _SubscriptionsAsync:
    def __init__(self, parent: "ArgusAsyncClient"):
        self._p = parent

    async def list(self) -> list[dict]:
        return await self._p._get_json("/api/v1/feed-subscriptions")

    async def create(
        self, *, name: str, filter: dict[str, Any],
        channels: list[dict[str, Any]], active: bool = True,
    ) -> dict:
        body = {"name": name, "filter": filter,
                "channels": channels, "active": active}
        return await self._p._post_json("/api/v1/feed-subscriptions", body)

    async def delete(self, subscription_id: str) -> None:
        await self._p._delete(f"/api/v1/feed-subscriptions/{subscription_id}")


class _IntelAsync:
    def __init__(self, parent: "ArgusAsyncClient"):
        self._p = parent

    async def sigma_backends(self) -> list[str]:
        out = await self._p._get_json("/api/v1/intel/sigma/backends")
        if isinstance(out, dict) and "backends" in out:
            return list(out["backends"])
        return out  # type: ignore[return-value]

    async def yara_availability(self) -> dict:
        return await self._p._get_json("/api/v1/intel/yara/availability")

    async def taxii_collections(self) -> dict:
        return await self._p._get_json("/taxii2/collections/")

    async def cves(
        self, *,
        cve_id: str | None = None,
        limit: int = 100,
    ) -> list[dict] | dict:
        if cve_id:
            return await self._p._get_json(f"/api/v1/intel/cves/{cve_id}")
        return await self._p._get_json(
            "/api/v1/intel/cves", params={"limit": limit},
        )


class ArgusAsyncClient:
    """Async mirror of ``ArgusClient``. Same auth + error semantics."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        access_token: str | None = None,
        timeout: float = 30.0,
        verify: bool | str = True,
    ):
        self._base = base_url.rstrip("/")
        self._api_key = api_key or ""
        self._access_token = access_token or ""
        self._http = httpx.AsyncClient(
            base_url=self._base, timeout=timeout, verify=verify,
            follow_redirects=True,
        )
        self.alerts = _AlertsAsync(self)
        self.iocs = _IOCsAsync(self)
        self.feeds = _FeedsAsync(self)
        self.subscriptions = _SubscriptionsAsync(self)
        self.intel = _IntelAsync(self)

    async def login(self, email: str, password: str) -> "ArgusAsyncClient":
        out = await self._post_json("/api/v1/auth/login",
                                     {"email": email, "password": password},
                                     _auth_required=False)
        self._access_token = out.get("access_token") or ""
        if not self._access_token:
            raise ArgusError(500, "no access_token in login response")
        return self

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "ArgusAsyncClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _headers(self, *, auth_required: bool = True) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if auth_required:
            if self._access_token:
                h["Authorization"] = f"Bearer {self._access_token}"
            elif self._api_key:
                h["X-API-Key"] = self._api_key
        return h

    def _check(self, resp: httpx.Response) -> Any:
        if resp.status_code < 200 or resp.status_code >= 300:
            try:
                detail = resp.json().get("detail") or resp.text
            except ValueError:
                detail = resp.text
            raise ArgusError(
                resp.status_code, str(detail)[:500],
                request_url=str(resp.request.url),
            )
        if not resp.content:
            return None
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    async def _get_json(self, path: str, *, params: dict | None = None) -> Any:
        r = await self._http.get(path, params=params, headers=self._headers())
        return self._check(r)

    async def _post_json(
        self, path: str, body: Any, *, _auth_required: bool = True,
    ) -> Any:
        r = await self._http.post(
            path, json=body,
            headers=self._headers(auth_required=_auth_required),
        )
        return self._check(r)

    async def _delete(self, path: str) -> Any:
        r = await self._http.delete(path, headers=self._headers())
        return self._check(r)
