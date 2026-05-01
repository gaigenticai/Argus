# United Arab Emirates (UAE) sovereign deployment

## Provider options

| Provider | Region | Sovereign? | Best for |
|---|---|---|---|
| **G42 / Core42** | Abu Dhabi | Yes — G42 is the UAE national-AI company; Core42 is the sovereign-cloud arm | Government, regulated finance, AI workloads |
| **Khazna Data Centers** | Abu Dhabi + Ras Al Khaimah | Yes — Etisalat-backed, Tier-IV facilities | Telco, enterprise |
| **e& Cloud** | Abu Dhabi | Yes — Etisalat / e& Group | Enterprise, telco |
| AWS me-central-1 (Dubai) | Dubai | Partial — sovereign-cloud option via separate contract | Buyers OK with global cloud + UAE residency addendum |
| Microsoft Azure UAE Central / North | Abu Dhabi / Dubai | Partial — same model as AWS | Microsoft-shop buyers |

## Recommended stack: G42 / Core42 (regulated finance)

Core42's Sovereign Cloud is the cleanest fit for ADHICS-regulated
healthcare and CBUAE-regulated banks. They provide local AAD-style
identity, VPC isolation, and a managed Kubernetes service.

### 1. Procurement

- Engage Core42 directly or through their certified system integrators
- Obtain **NESA / TDRA Information Assurance certification** for the
  deployment
- For healthcare buyers: ensure the deployment falls under the
  **DoH ADHICS v2** scope and provide the operator's compliance
  attestation

### 2. Network layout

```
Public Internet (TLS 443) ──┐
                            ▼
            Core42 Application Gateway (WAF + TLS)
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
     argus-api        argus-worker        argus-tor
     (3 replicas)     (1 replica)         (egress only)
          │                 │
          └─────┬───────────┘
                ▼
     Private VPC (10.20.0.0/16)
     ├─ Core42 Managed PostgreSQL
     ├─ Core42 Redis
     ├─ Core42 Object Storage
     └─ Core42 Inception (managed Falcon LLM endpoint)
```

### 3. Sizing (production)

Same as KSA. For Falcon-LLM-via-Inception customers, drop the GPU
node — Core42's managed Falcon endpoint replaces it.

### 4. Argus configuration

```bash
# Tenant locale → UAE
ARGUS_DEFAULT_TIMEZONE=Asia/Dubai
ARGUS_DEFAULT_CALENDAR=gregorian   # UAE banking defaults to Gregorian

# Object storage → Core42
ARGUS_EVIDENCE_ENDPOINT_URL=https://oss.core42.ae
ARGUS_EVIDENCE_REGION=core42-abu-dhabi-1
ARGUS_EVIDENCE_BUCKET=argus-evidence

# DB → Core42 managed Postgres
ARGUS_DB_HOST=argus-pg.core42.ae

# LLM — Core42 Inception (Falcon 180B) OR BYOK Anthropic
ARGUS_LLM_PROVIDER=openai_compatible
ARGUS_LLM_BASE_URL=https://inception.core42.ae/v1
ARGUS_LLM_API_KEY=<customer's Inception key>
ARGUS_LLM_MODEL=falcon-180B-chat

# Compliance frameworks: NESA-IA + ADHICS (healthcare) +
#                        ISO 27001 + GDPR (cross-border subsidiaries)
ARGUS_COMPLIANCE_FRAMEWORKS=NESA-IA-V2,ADHICS-V2,ISO-27001-2022
```

### 5. Compliance evidence

Argus's Compliance Evidence Pack ships pre-mapped to **TDRA
Information Assurance Regulation** (NESA v2) and **ADHICS v2** for
healthcare. UAE Pass / Nafath OTP phishing patterns are baked into
the Arabic phishing analyzer (P1 #1.6) so the Detection Engineering
team's evidence pack already covers the most common UAE pretexts.

### 6. Key NESA / TDRA / ADHICS expectations

| Requirement | Argus answer |
|---|---|
| Information Security Risk Assessment (NESA T1.5) | Compliance evidence pack |
| Threat & Vulnerability Management (NESA T2.5) | Threat intel + EASM + vuln-intel feeds |
| Security Monitoring (NESA T3.6) | Continuous monitoring + Iran-APT auto-tag |
| Email & Web Defence (NESA T4.4) | Arabic phishing analyzer with UAE Pass + ICA pretexts |
| Incident Response (NESA T7.5) | Cases module |
| Healthcare Data Protection (ADHICS DM.5) | DLP + leakage modules |
| Healthcare Threat Intel (ADHICS IM.3) | Argus core |

### 7. Buyer contracting checklist

- [ ] Core42 master service agreement signed
- [ ] Argus / Marsad reseller agreement signed
- [ ] NESA / TDRA certification obtained
- [ ] ADHICS attestation (healthcare only)
- [ ] CBUAE notification (banking only)
- [ ] Cross-border data transfer addendum (if applicable for subsidiaries)
- [ ] Penetration-test schedule agreed (annual minimum per NESA T2.14)
