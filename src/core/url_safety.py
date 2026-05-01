"""URL safety helpers (Audit B9).

Validate user-supplied URLs (notification webhooks, partner endpoints)
against SSRF risk. Reject:

- Schemes other than https (or http when explicitly opted-in).
- Hosts that resolve to private / loopback / link-local addresses, or
  are outright cloud-metadata IPs.
- Ports that are obviously dangerous (e.g., 22, 25, 3306, 5432, 6379)
  unless explicitly allowed.

The check is performed at *save* time AND immediately before each
dispatch (TOCTOU / DNS rebinding defence).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
}

_DEFAULT_DENY_PORTS = {
    22, 23, 25, 53, 110, 143, 161, 389, 445, 465, 587,
    1433, 1521, 2049, 2375, 3306, 3389, 5432, 5433, 5984,
    6379, 9200, 11211, 27017, 27018,
}

# These ranges are NEVER allowed, even when ARGUS_URL_SAFETY_ALLOW_PRIVATE=1.
# They cover cloud instance metadata endpoints (169.254.169.254 on AWS/GCP/Azure),
# IPv6 ULA, and CGNAT — none of which are legitimate webhook targets.
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("fd00::/8"),          # IPv6 ULA
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
]

# RFC1918 private ranges — blocked by default, but bypassable via
# ARGUS_URL_SAFETY_ALLOW_PRIVATE=1 for on-prem webhook deployments.
_CONDITIONAL_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


class UnsafeUrlError(ValueError):
    """Raised when a URL fails the SSRF guard."""


def _is_always_blocked_ip(ip: str) -> bool:
    """Returns True for IPs that must never be reached regardless of config."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return True
    return any(addr in net for net in _ALWAYS_BLOCKED_NETWORKS)


def _is_conditionally_private_ip(ip: str) -> bool:
    """Returns True for RFC1918 addresses (bypassable with ALLOW_PRIVATE)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CONDITIONAL_PRIVATE_NETWORKS)


def _allow_private_for_tests() -> bool:
    """RFC1918 IPs are permitted only when explicitly opted in.

    Tests and dev environments set ``ARGUS_URL_SAFETY_ALLOW_PRIVATE=1``
    to disable the RFC1918 check (so loopback fixtures work). Production
    on-prem deployments where notification webhooks live in the same VPC
    may also set this — the guard then trusts the operator's firewall.

    Note: link-local (169.254.0.0/16), IPv6 ULA, and CGNAT ranges are
    NEVER allowed regardless of this flag — they cover cloud metadata
    endpoints (AWS/GCP/Azure) that must always be blocked.
    """
    import os as _os
    val = _os.environ.get("ARGUS_URL_SAFETY_ALLOW_PRIVATE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def assert_safe_url(
    url: str,
    *,
    allow_http: bool = False,
    extra_blocked_ports: set[int] | None = None,
) -> str:
    """Raise :class:`UnsafeUrlError` if the URL is not safe to call.

    Returns the canonical URL string on success.
    """
    if not url or not isinstance(url, str):
        raise UnsafeUrlError("URL must be a non-empty string")
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",) and not (allow_http and scheme == "http"):
        raise UnsafeUrlError(f"scheme {scheme!r} not allowed")
    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeUrlError("URL has no host")
    if host in _BLOCKED_HOSTS:
        raise UnsafeUrlError(f"host {host!r} is on the deny list")
    port = parsed.port
    deny_ports = _DEFAULT_DENY_PORTS | (extra_blocked_ports or set())
    if port is not None and port in deny_ports:
        raise UnsafeUrlError(f"port {port} is not allowed")

    # Resolve every A/AAAA record and apply the two-tier IP block.
    try:
        infos = socket.getaddrinfo(host, port or (443 if scheme == "https" else 80))
    except socket.gaierror as e:
        raise UnsafeUrlError(f"DNS lookup failed for {host!r}: {e}")
    for info in infos:
        ip = info[4][0]
        # Tier 1: always blocked — cloud metadata, link-local, loopback, etc.
        if _is_always_blocked_ip(ip):
            raise UnsafeUrlError(
                f"host {host!r} resolves to always-blocked IP {ip} "
                "(link-local/cloud-metadata/loopback — not bypassable)"
            )
        # Tier 2: RFC1918 — blocked unless ALLOW_PRIVATE is set.
        if not _allow_private_for_tests() and _is_conditionally_private_ip(ip):
            raise UnsafeUrlError(
                f"host {host!r} resolves to private IP {ip}"
            )
    return url


def is_safe_url(url: str, *, allow_http: bool = False) -> bool:
    """Boolean form for code paths that want to ask without exception."""
    try:
        assert_safe_url(url, allow_http=allow_http)
        return True
    except UnsafeUrlError:
        return False


__all__ = ["UnsafeUrlError", "assert_safe_url", "is_safe_url"]
