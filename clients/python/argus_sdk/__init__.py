"""Argus Python SDK (P3 #3.4).

Thin, hand-written wrapper over the Argus REST API. Generated codegen
(see scripts/generate_sdks.sh) produces a 1:1 mapping of every endpoint;
this SDK is the *curated* surface a typical customer integration needs:
authenticate, list/fetch alerts, list/fetch IOCs, push to TAXII subset,
manage feed subscriptions, run intel reads (sigma/yara/sandbox/etc.).

Usage:

    from argus_sdk import ArgusClient

    client = ArgusClient(
        base_url="https://argus.bank.example",
        api_key="...",                 # X-API-Key header
    )
    # Or username/password:
    client = ArgusClient(base_url="...").login("alice@bank", "pw")

    for alert in client.alerts.list(severity="critical"):
        print(alert["title"])

The client is sync by default for ergonomic notebook / script use; the
``ArgusAsyncClient`` mirrors the same surface for async callers.
"""

from .client import ArgusAsyncClient, ArgusClient, ArgusError

__all__ = ["ArgusClient", "ArgusAsyncClient", "ArgusError"]
__version__ = "0.1.0"
