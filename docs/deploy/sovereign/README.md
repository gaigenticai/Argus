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
