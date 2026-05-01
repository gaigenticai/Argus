# Generic / Railway / self-hosted Kubernetes

For buyers who don't need a sovereign cloud — pilots, lab installs,
small enterprises — Argus runs on the generic Kubernetes path with
zero region pinning.

## Quick start: Railway

[Railway](https://railway.app/) is the fastest "one-click deploy" for
proof-of-concept installs. It's not a sovereign cloud, so don't use
it for regulated production — but it gets a demo into the buyer's
hands inside 10 minutes.

```bash
# 1. Install the Railway CLI
npm install -g @railway/cli
railway login

# 2. Provision Postgres + Redis + Object Storage
railway init argus-demo
railway add --plugin postgresql
railway add --plugin redis

# 3. Deploy from the Argus repo
railway up

# 4. Set required secrets via the Railway UI or CLI
railway variables set ARGUS_JWT_SECRET=$(openssl rand -hex 32)
railway variables set ARGUS_BOOTSTRAP_ADMIN_EMAIL=admin@demo.tld
railway variables set ARGUS_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 24)
railway variables set ARGUS_BOOTSTRAP_ANALYST_EMAIL=analyst@demo.tld
railway variables set ARGUS_BOOTSTRAP_ANALYST_PASSWORD=$(openssl rand -base64 24)

# 5. Run the realistic seed
railway run python -m scripts.seed.realistic
```

## Generic Kubernetes (Helm)

The reference Helm chart at [`helm/argus/`](../../../helm/argus/)
targets vanilla Kubernetes 1.27+ on any provider with:

- a CSI driver (for `argus-postgres`, `argus-meilisearch`,
  `argus-evidence` PVCs)
- an ingress controller (nginx / Traefik / Istio gateway)
- a way to expose secrets (Sealed Secrets / external-secrets / SOPS)

### Install

```bash
# Add custom values for your cluster
cat > values.local.yaml <<EOF
ingress:
  enabled: true
  hostname: argus.example.com
  className: nginx
  tls:
    - secretName: argus-tls
      hosts: [argus.example.com]

argus:
  jwtSecret: <pinned-from-secret-manager>
  bootstrapAdmin:
    email: admin@example.com
    password: <pinned-from-secret-manager>

postgres:
  persistence:
    size: 100Gi
  resources:
    requests:
      memory: 8Gi
      cpu: 4

evidence:
  endpoint: https://s3.example.com
  bucket: argus-evidence
  accessKey: <pinned>
  secretKey: <pinned>
EOF

helm install argus ./helm/argus -f values.local.yaml -n argus --create-namespace
```

### Bring-your-own infrastructure

If the customer already has managed Postgres + Redis + S3, drop the
embedded bitnami subcharts:

```yaml
postgres:
  enabled: false
  external:
    host: customer-postgres.internal
    port: 5432
    database: argus
    secret: argus-pg-creds   # contains ARGUS_DB_PASSWORD

redis:
  enabled: false
  external:
    url: redis://customer-redis:6379

evidence:
  external:
    endpoint: https://s3.amazonaws.com
    region: eu-west-1
    bucket: customer-argus-evidence
```

This is the cleanest path for buyers who already run their stack on
the cloud they prefer — Argus just talks to the existing Postgres /
Redis / S3 they've procured.

### Resource defaults

The chart's default `resources` blocks are tuned for a 50-user
deployment producing ~1000 alerts/day. Scale up Postgres (NVMe + RAM)
first if you exceed that volume.

| Component | CPU req / lim | Memory req / lim | Notes |
|---|---|---|---|
| `argus-api` | 500m / 2000m | 512Mi / 2Gi | 3 replicas |
| `argus-worker` | 1000m / 4000m | 1Gi / 4Gi | 1 replica (singleton scheduler) |
| `argus-tor` | 100m / 500m | 256Mi / 1Gi | 1 replica |
| `postgres` | 2000m / 8000m | 4Gi / 16Gi | RWX or single-attach RWO |
| `redis` | 200m / 1000m | 256Mi / 2Gi | persistence on |
| `meilisearch` | 500m / 2000m | 512Mi / 4Gi | 50Gi PVC |

## Helm chart reference

See `helm/argus/values.yaml` for the full configurable surface. Every
ARGUS_* env var documented in `.env.example` has a matching Helm value.
