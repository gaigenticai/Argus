# Saudi Arabia (KSA) sovereign deployment

## Provider options

| Provider | Region | Sovereign? | Best for |
|---|---|---|---|
| **STC Cloud** | Riyadh + Jeddah | Yes — STC is the national telecom; data stays in-Kingdom | Banks (SAMA-regulated), SAMA Cyber Security Framework compliance |
| **Mobily Cloud** | Riyadh | Yes — Mobily Etihad Etisalat | Government, telco-adjacent buyers |
| **Oracle Cloud (Jeddah / Riyadh region)** | OCI Sovereign Cloud KSA | Yes — operationally separated from global Oracle Cloud, Saudi staff only | Buyers requiring Oracle DB compatibility, large enterprises |
| Google Cloud Dammam | Dammam | Partial — sovereign controls available but parent infra is global Google | Buyers OK with global cloud + Saudi data-residency contractual addendum |

## Recommended stack: STC Cloud (banking)

For a SAMA-regulated bank, STC Cloud is the safest default. Their
Banking Cloud product satisfies SAMA-CSF + NCA-ECC + NDMO data-
residency requirements out of the box.

### 1. Procurement

- Contract through your local Argus / Marsad reseller (they have a
  STC Cloud Marketplace SKU)
- Obtain **NCA-ECC certificate of compliance** for the deployment
  (your reseller's compliance team handles this)
- Sign STC's standard data-processing addendum

### 2. Network layout

```
Public Internet (TLS 443) ──┐
                            ▼
              Argus ALB (STC Load Balancer)
                            │
              ┌─────────────┼────────────────┐
              ▼             ▼                ▼
         argus-api     argus-worker     argus-tor (egress
        (3 replicas)   (1 replica)     to clearnet only via
                                       NAT GW; no inbound)
              │             │
              └─────┬───────┘
                    ▼
       Private VPC subnet (10.10.0.0/16)
       ├─ PostgreSQL Flex (managed)
       ├─ Redis Cluster (managed)
       ├─ STC Object Storage (S3-compat)
       └─ Optional: GPU node for Gemma 3 27B
```

### 3. Sizing (production)

| Component | vCPU | RAM | Storage |
|---|---|---|---|
| `argus-api` | 4 vCPU × 3 | 8 GB × 3 | n/a (stateless) |
| `argus-worker` | 8 vCPU | 16 GB | n/a |
| `argus-tor` | 2 vCPU | 2 GB | n/a |
| PostgreSQL | 16 vCPU | 64 GB | 500 GB NVMe + 7-day backups |
| Redis | 4 vCPU | 8 GB | n/a (in-memory) |
| Meilisearch | 4 vCPU | 8 GB | 100 GB NVMe |
| MinIO / Object Storage | 4 vCPU | 8 GB | 1 TB (with cross-AZ replication) |
| GPU (optional, for local Gemma 3 27B) | 1× A100 40GB | 64 GB | 200 GB NVMe |

### 4. Argus configuration

```bash
# Tenant locale → KSA
ARGUS_DEFAULT_TIMEZONE=Asia/Riyadh
ARGUS_DEFAULT_CALENDAR=islamic-umalqura

# Object storage → STC Object Storage (S3-compatible)
ARGUS_EVIDENCE_ENDPOINT_URL=https://objectstorage.stccloud.sa
ARGUS_EVIDENCE_REGION=stc-riyadh-1
ARGUS_EVIDENCE_BUCKET=argus-evidence

# DB → STC managed Postgres
ARGUS_DB_HOST=argus-postgres.stccloud.sa
ARGUS_DB_PORT=5432
ARGUS_DB_NAME=argus
ARGUS_DB_USER=argus_app
# password from STC secret manager

# Redis → STC managed
ARGUS_HOST_REDIS_PORT=6380

# LLM — BYOK Anthropic OR Gemma 3 27B via Ollama on the GPU node
ARGUS_LLM_PROVIDER=ollama
ARGUS_LLM_OLLAMA_HOST=http://ollama.svc:11434
ARGUS_LLM_MODEL=gemma3:27b

# (or Anthropic BYOK)
# ARGUS_LLM_PROVIDER=anthropic
# ARGUS_LLM_API_KEY=<customer's key>

# SAMA Cyber Security Framework + NCA-ECC compliance pack auto-export
ARGUS_COMPLIANCE_FRAMEWORKS=NCA-ECC-V2,SAMA-CSF-V1,ISO-27001-2022
```

### 5. Compliance evidence

Argus's Compliance Evidence Pack (P1 #1.3) ships pre-mapped to
**NCA-ECC v2** + **SAMA-CSF v1.0**. Generate the bilingual export
from the dashboard → Compliance → New export, framework =
`NCA-ECC-V2`, language = `bilingual`. Hand the resulting PDF to the
SAMA examiner.

### 6. Key SAMA / NCA expectations

| Requirement | Argus answer |
|---|---|
| Cyber Security Strategy (SAMA 3.3.1) | Documented in compliance evidence pack |
| Threat Intelligence (SAMA 3.3.13 / NCA-ECC 2-12) | Argus IS the threat intelligence platform |
| Incident Management (SAMA 3.3.6 / NCA-ECC 2-11) | Cases module + IR runbooks |
| Vulnerability Management (SAMA 3.3.14 / NCA-ECC 2-13) | EASM + GHSA + ExploitDB feed integration |
| Brand Protection (SAMA 3.3.16) | Brand Protection module + GCC ransomware filter |
| Cybersecurity Logs (NCA-ECC 2-10) | Audit log + retention worker |
| Third-Party Cybersecurity (NCA-ECC 4-1) | TPRM module |

### 7. Buyer contracting checklist

- [ ] STC Cloud master agreement signed
- [ ] STC Banking Cloud add-on signed
- [ ] Argus / Marsad reseller agreement signed
- [ ] NCA-ECC certificate of compliance obtained
- [ ] SAMA notification submitted (regulated buyers only)
- [ ] Data-processing addendum signed by both parties
- [ ] Penetration-test schedule agreed (annual minimum per NCA-ECC 2-14)
- [ ] BCP / DR plan documented + signed off
