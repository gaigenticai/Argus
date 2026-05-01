# Argus Python SDK

Official Python client for the Argus / Marsad threat-intelligence platform.

```bash
pip install argus-sdk
```

```python
from argus_sdk import ArgusClient

with ArgusClient(base_url="https://argus.bank.example",
                 api_key="argus_...") as client:
    for alert in client.alerts.list(severity="critical", limit=20):
        print(alert["title"])

    # Subscribe a webhook to all critical phishing alerts
    sub = client.subscriptions.create(
        name="Phishing → SOC webhook",
        filter={"severity": ["critical", "high"], "category": "phishing"},
        channels=[{"type": "webhook",
                   "url": "https://soc.bank/argus-hook"}],
    )
```

The async equivalent (`ArgusAsyncClient`) mirrors the same surface:

```python
from argus_sdk import ArgusAsyncClient

async with ArgusAsyncClient(base_url="...", api_key="...") as client:
    alerts = await client.alerts.list(severity="critical")
```

## Authentication

Two paths:

- **API key** — set `api_key=...` at construction. Sent as `X-API-Key`.
- **Username / password** — call `client.login(email, password)` after
  construction. Stores the JWT access token on the client.

## Surface

The SDK is a *curated* slice of the full Argus API. For full coverage,
fetch the OpenAPI 3.1 schema and codegen:

```bash
curl https://argus.example/openapi.json > argus.openapi.json
# or use the checked-in copy at clients/openapi/argus.openapi.json
scripts/generate_sdks.sh py
```

The schema is also versioned in this repo at
[`clients/openapi/argus.openapi.json`](../openapi/argus.openapi.json).

## Errors

Every non-2xx response raises `ArgusError(status, detail)`. Catch and
inspect:

```python
from argus_sdk import ArgusClient, ArgusError

try:
    client.alerts.get("nope")
except ArgusError as exc:
    if exc.status == 404:
        ...
```
