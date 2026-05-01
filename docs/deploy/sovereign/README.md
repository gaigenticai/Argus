# Argus sovereign deployment guides

These guides cover the **GCC + EU sovereign-cloud** deployment paths
required for regulated buyers. Each provider has its own residency,
contracting, and compliance footprint — pick the one that matches
the buyer's data-localisation regulator.

## Why sovereign at all

GCC banking + government buyers explicitly require:
- **Data residency** — every byte of customer data physically in-region
- **Local contracting entity** — invoicing through a GCC corporate
- **Operator separation** — no foreign engineering staff with prod console access

The five providers below all satisfy those constraints. Argus runs
unchanged on each — what differs is the network plumbing, the storage
backend, and the contracting paperwork the operator hands the buyer's
procurement team.

## Index

| Region | Recommended provider(s) | Guide |
|---|---|---|
| 🇸🇦 KSA | STC Cloud · Mobily Cloud · Oracle Jeddah/Riyadh | [`ksa.md`](./ksa.md) |
| 🇦🇪 UAE | G42 / Core42 · Khazna · e& Cloud | [`uae.md`](./uae.md) |
| 🇶🇦 Qatar | Ooredoo Cloud · Qatar National Cloud | [`qatar.md`](./qatar.md) |
| 🇪🇺 EU | OVH · Hetzner | [`eu.md`](./eu.md) |
| Generic | Railway sovereign region · self-hosted Kubernetes | [`railway.md`](./railway.md) |

## Common architecture

Every sovereign deployment runs the same eight components:

```
                ┌──────────────────────────────────────────────┐
                │                  Argus tenant                 │
                ├──────────────────────────────────────────────┤
                │  argus-api   (FastAPI · uvicorn · 2-4 vCPU)  │
                │  argus-worker (feed scheduler + agents)      │
                │  argus-tor   (Tor SOCKS5 + control)          │
                │  postgres    (16+ vCPU, 50+ GB RAM, NVMe)    │
                │  redis       (4 GB, persistent)              │
                │  minio (or S3-compat) — evidence vault       │
                │  meilisearch — full-text search              │
                │  ollama (optional) — Gemma 3 27B local LLM   │
                └──────────────────────────────────────────────┘
```

Argus is **single-tenant on-prem** in v1 — one customer per install.
For MSSP scenarios with multiple sub-tenants, see P3 #3.1
(multi-tenant mode, in progress).

## Helm chart

A reference Helm chart ships at [`helm/argus/`](../../../helm/argus/).
It targets vanilla Kubernetes 1.27+ with a compatible CSI driver for
PVCs. The README in that directory documents the values surface.

Most sovereign clouds offer managed Kubernetes (RKE2 / OpenShift / EKS-
compatible) — point your `helm install` at that cluster and the rest
of the deployment is identical to a generic Kubernetes target.

## Deployment checklist

Use this checklist as a single page in the buyer's procurement RFP
response. Every cell maps to a sovereign requirement most regulators
audit:

- [ ] All compute resources in the regulator's geography (no foreign egress)
- [ ] Postgres encrypted at rest (provider KMS) + TLS-only ingress
- [ ] MinIO / S3 bucket-level encryption + signed-URL TTL ≤ 1 h
- [ ] TLS certificate from a regulator-trusted CA (Let's Encrypt is fine for KSA / UAE / Qatar; EU procurement sometimes requires national CAs)
- [ ] Per-org admin/analyst credentials provisioned from buyer's IdP via SAML or OIDC
- [ ] Customer's existing SIEM connector configured (see `/intel/siem/connectors`)
- [ ] Tenant locale set to local TZ + Hijri/Gregorian calendar via `/api/v1/organizations/current/locale`
- [ ] Compliance Evidence Pack export tested for at least one regulator framework (NCA-ECC / SAMA-CSF / NESA / Qatar NIA / GDPR)
- [ ] Backup policy: daily Postgres `pg_dump` + MinIO mirror to second region within the same country
- [ ] Disaster-recovery plan documented + RPO/RTO acknowledged by buyer
- [ ] Security monitoring: container runtime + host-level EDR running on the operator's side
- [ ] Sovereign-cloud-specific contracting paperwork attached

## Phase 3 connector credentials

Every P3 vendor / tooling connector is opt-in. Each is wired through
`helm/argus/templates/secret.yaml`; pin the value via your secret
manager (Vault / AWS Secrets Manager / GCP Secret Manager / Sealed
Secrets / External Secrets Operator). Empty values keep the connector
dormant; `is_configured()` returns `false` and every entry-point is a
clean no-op.

| Group | Env vars | Notes |
| --- | --- | --- |
| **EDR** | `ARGUS_FALCON_CLIENT_ID/SECRET/BASE_URL`, `ARGUS_S1_API_TOKEN/BASE_URL`, `ARGUS_MDE_TENANT_ID/CLIENT_ID/CLIENT_SECRET` | CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint. |
| **Email gateway** | `ARGUS_PROOFPOINT_PRINCIPAL/SECRET`, `ARGUS_MIMECAST_BASE_URL/APP_ID/APP_KEY/ACCESS_KEY/SECRET_KEY`, `ARGUS_ABNORMAL_TOKEN` | Mimecast `SECRET_KEY` is the **base64-encoded** secret per Mimecast 2.0 docs. |
| **Sandbox** | `ARGUS_CAPE_URL/API_KEY`, `ARGUS_JOE_API_KEY`, `ARGUS_HYBRID_API_KEY`, `ARGUS_VT_API_KEY` + `ARGUS_VT_ENTERPRISE=true` | VirusTotal requires both the key **and** the explicit `ARGUS_VT_ENTERPRISE=true` opt-in (free-tier ToS forbids commercial-product use). |
| **SOAR** | `ARGUS_XSOAR_URL/API_KEY/KEY_ID`, `ARGUS_TINES_WEBHOOK_URL`, `ARGUS_SPLUNK_SOAR_URL/TOKEN` | Cortex XSOAR, Tines, Splunk SOAR (Phantom). |
| **Breach providers** | `ARGUS_HIBP_API_KEY`, `ARGUS_INTELX_API_KEY`, `ARGUS_DEHASHED_API_KEY` | All commercially-licensable, BYOK. |
| **Forensics** | `ARGUS_VOLATILITY_CLI`, `ARGUS_FORENSICS_IMAGE_DIR`, `ARGUS_VELOCIRAPTOR_URL/TOKEN/VERIFY_SSL` | `ARGUS_FORENSICS_IMAGE_DIR` chroots Volatility memory-image input paths; recommend `/var/lib/argus/forensics`, mode 0700. |
| **Adversary emulation** | `ARGUS_ATOMIC_RED_TEAM_PATH`, `ARGUS_CALDERA_URL/API_KEY` | Atomic Red Team is opt-in (mount the `atomics/` directory); curated 14-test starter ships when the path is unset. |
| **Telegram (legal-gated)** | `ARGUS_TELEGRAM_ENABLED=true`, `ARGUS_TELEGRAM_API_ID/API_HASH/SESSION_PATH` | Operator must complete legal review before flipping `ARGUS_TELEGRAM_ENABLED=true`. The session-DB **parent directory** must be mode `0700` and owned by the api-process uid — Telethon writes the user's auth-key material there, and the health-check route flags this loudly when the parent dir is world-readable. |

After installing or re-installing the chart, hit
`/api/v1/intel/<group>/connectors` (or the dashboard `/connectors`
page) to verify that every expected connector reports
`configured: true`.
