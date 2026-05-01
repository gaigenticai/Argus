# EU sovereign deployment

## Provider options

| Provider | Headquarters | Sovereign? | Best for |
|---|---|---|---|
| **OVHcloud** | Roubaix, France | Yes — French Schrems II compliant; SecNumCloud (ANSSI) certified options | Banking, government, GDPR-strict buyers |
| **Hetzner** | Gunzenhausen, Germany | Yes — German DSGVO compliant; EU-only data centres | Cost-sensitive enterprise, ISO 27001 baseline |
| **Scaleway** | Paris, France | Yes — French sovereign cloud | Tech-forward enterprises |
| Stackit (Schwarz Group) | Heilbronn, Germany | Yes — German sovereign cloud | Retail, manufacturing |

## Recommended stack: OVHcloud (regulated finance)

OVH's **SecNumCloud** offering is the cleanest fit for EU regulated
buyers (banking under PSD2, DORA, NIS2). It's certified by ANSSI
(France's national security agency) and accepted by all EU national
banking regulators.

### 1. Procurement

- Order via OVH Sales (SecNumCloud requires sales-handled signup)
- Choose region: Roubaix, Strasbourg, or Gravelines (all EU + ANSSI)
- Sign **EU Standard Contractual Clauses** + **Schrems II
  Transfer Impact Assessment**

### 2. Network + sizing

OVH provides bare-metal, public cloud (OpenStack-based), and
managed-Kubernetes. For Argus, the managed-Kubernetes path is
cheapest; bare-metal is faster but operationally heavier.

### 3. Argus configuration

```bash
# Locale — EU defaults
ARGUS_DEFAULT_TIMEZONE=Europe/Paris   # Frankfurt / Brussels also fine
ARGUS_DEFAULT_CALENDAR=gregorian

# OVH Object Storage (S3-compatible)
ARGUS_EVIDENCE_ENDPOINT_URL=https://s3.gra.cloud.ovh.net
ARGUS_EVIDENCE_REGION=GRA
ARGUS_EVIDENCE_BUCKET=argus-evidence

# OVH managed Postgres
ARGUS_DB_HOST=argus-pg.gra1.databases.ovh.net

# LLM — BYOK Anthropic (EU-routed)
# OR Ollama + Gemma 3 27B running locally (no egress)
ARGUS_LLM_PROVIDER=ollama
ARGUS_LLM_OLLAMA_HOST=http://ollama.svc:11434
ARGUS_LLM_MODEL=gemma3:27b

# Compliance frameworks — EU-relevant
ARGUS_COMPLIANCE_FRAMEWORKS=ISO-27001-2022,NIST-CSF-V2,PCI-DSS-V4,SOC2-CC7
```

### 4. EU regulatory expectations

| Regulation | Argus answer |
|---|---|
| **GDPR Article 32** (security of processing) | Compliance evidence pack + audit log |
| **DORA Article 6** (ICT risk management framework) | Cases + retention + audit log |
| **DORA Article 17** (ICT-related incident management) | Cases module + IR runbooks + notification templates |
| **DORA Article 24** (advanced testing — TLPT) | EASM + adversary-emulation hooks (P3 #3.5) |
| **DORA Article 28** (third-party arrangements) | TPRM module |
| **NIS2 Article 21** (cybersecurity risk-management measures) | Compliance evidence pack |
| **PCI-DSS 4.0.1** (any merchant or processor) | Compliance evidence pack pre-mapped |

### 5. Buyer contracting checklist

- [ ] OVHcloud SecNumCloud master agreement signed
- [ ] EU SCCs + Schrems II TIA completed
- [ ] DORA register-of-information entry filed
- [ ] NIS2 competent authority notification (member state-specific)
- [ ] BCP / DR plan documented per DORA Article 11
- [ ] Penetration-test schedule per DORA Article 24 (TLPT for
       in-scope financial entities)
