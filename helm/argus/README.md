# Argus Helm chart

Vanilla Kubernetes 1.27+ install for the Argus Threat Intelligence
platform. Read the sovereign-cloud guides at
[`docs/deploy/sovereign/`](../../docs/deploy/sovereign/) before
production deployment.

## Quick install

```bash
helm install argus ./helm/argus -n argus --create-namespace
```

The default `values.yaml` ships an in-cluster Postgres + Redis +
MinIO + Meilisearch with **dev-only passwords**. Override every
`CHANGE_ME_*` value before any non-toy install.

## Bring-your-own infrastructure

Pin to managed services by disabling the embedded subcharts:

```yaml
postgres: { enabled: false, external: { host: pg.internal, port: 5432, secret: argus-pg } }
redis:    { enabled: false, external: { url: redis://r.internal:6379 } }
evidence: { enabled: false, external: { endpoint: https://s3.amazonaws.com, region: eu-west-1, bucket: argus-evidence, accessKey: ..., secretKey: ... } }
```

## Chart components

```
helm/argus/
├── Chart.yaml
├── values.yaml          (full configurable surface)
├── README.md
└── templates/
    ├── _helpers.tpl
    ├── secret.yaml      (consolidated ARGUS_* env)
    ├── api-deployment.yaml
    ├── api-service.yaml
    ├── worker-deployment.yaml
    ├── tor-deployment.yaml
    ├── postgres-statefulset.yaml
    ├── redis-deployment.yaml
    ├── meilisearch-statefulset.yaml
    ├── evidence-statefulset.yaml   (MinIO)
    ├── ollama-statefulset.yaml     (optional, GPU)
    ├── ingress.yaml
    └── serviceaccount.yaml
```

The chart ships with the **secret + service + ingress** templates
populated; the StatefulSet/Deployment templates accept any image
override via `values.yaml`. For a full production deployment, fork
the chart and add provider-specific bits (CSI driver class, IRSA
annotations, Pod Security Policies …).

## Compatibility matrix

| Provider | Tested? | Storage class | Notes |
|---|---|---|---|
| KSA / STC Cloud | ✅ | `stc-nvme` | See `docs/deploy/sovereign/ksa.md` |
| UAE / Core42 | ✅ | `core42-premium` | See `docs/deploy/sovereign/uae.md` |
| Qatar / Ooredoo | ✅ | `ooredoo-ssd` | See `docs/deploy/sovereign/qatar.md` |
| OVHcloud | ✅ | `csi-cinder-high-speed` | SecNumCloud option |
| Hetzner | ✅ | `hcloud-volumes` | EU |
| Generic K8s | ✅ | depends on cluster | Validate CSI driver supports RWO |

## What this chart does NOT do

- It does not bundle the customer's SIEM / SOAR / breach providers — those are env-var configured at runtime against external endpoints
- It does not run the Argus database migrations — run `python -m alembic upgrade head` from a Job after first install
- It does not seed demo data — run `python -m scripts.seed.realistic` from a Job for demo / pilot environments

## Resource defaults

Tuned for ~50 active users + ~1 000 alerts/day. Scale Postgres first
when you exceed that volume — the rest of the components are CPU-
elastic.

| Component | CPU req / lim | Memory req / lim |
|---|---|---|
| `argus-api` | 500m / 2000m | 512Mi / 2Gi |
| `argus-worker` | 1000m / 4000m | 1Gi / 4Gi |
| `argus-tor` | 100m / 500m | 256Mi / 1Gi |
| `postgres` | 2000m / 8000m | 4Gi / 16Gi |
| `redis` | 200m / 1000m | 256Mi / 2Gi |
| `meilisearch` | 500m / 2000m | 512Mi / 4Gi |
