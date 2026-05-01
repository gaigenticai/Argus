# Qatar sovereign deployment

## Provider options

| Provider | Region | Sovereign? | Best for |
|---|---|---|---|
| **Ooredoo Cloud** | Doha | Yes — Ooredoo is Qatar's national telecom | Most regulated buyers |
| **Qatar National Cloud (Q-CERT-aligned)** | Doha | Yes — government-operated | Government, MoI, MoF |
| **MEEZA Tier-IV Data Center** | Doha | Yes — Qatari data-center operator | Enterprise colocation |

## Recommended stack: Ooredoo Cloud

Ooredoo Cloud's Q-CERT-aligned offering is the clean default for
Qatar Central Bank (QCB) and Q-CERT NIA Policy v2 buyers.

### 1. Procurement

- Engage Ooredoo Cloud Business directly
- Obtain **Q-CERT NIA Policy v2 attestation** for the deployment
- For QCB-regulated banks: notify QCB Banking Supervision per
  Banking Cybersecurity Manual

### 2. Network + sizing

Same shape as KSA / UAE. Ooredoo Cloud's managed-Postgres,
managed-Redis, and S3-compatible object storage map 1:1 to Argus's
expectations. Use 1 Tbps Ooredoo intra-Qatar private network for
the inter-component traffic.

### 3. Argus configuration

```bash
ARGUS_DEFAULT_TIMEZONE=Asia/Qatar
ARGUS_DEFAULT_CALENDAR=gregorian

ARGUS_EVIDENCE_ENDPOINT_URL=https://obj.ooredoo-cloud.qa
ARGUS_EVIDENCE_REGION=ooredoo-doha-1
ARGUS_EVIDENCE_BUCKET=argus-evidence
ARGUS_DB_HOST=argus-pg.ooredoo-cloud.qa

# QatarEnergy / Ooredoo / QNB pretexts already covered by the
# Arabic phishing analyzer (P1 #1.6).
ARGUS_COMPLIANCE_FRAMEWORKS=QATAR-NIA-V2,ISO-27001-2022,NIST-CSF-V2
```

### 4. Q-CERT NIA Policy v2 expectations

| Requirement | Argus answer |
|---|---|
| Risk Management (NIA SM-3) | Compliance evidence pack |
| Threat Intelligence Acquisition (NIA TI-1) | Argus core |
| Vulnerability Identification (NIA VM-1) | EASM + vuln feeds |
| Logging & Monitoring (NIA CM-3) | Audit log + SIEM connectors |
| Incident Response (NIA IM-2) | Cases module + Q-CERT notification template |
| Continuous Asset Monitoring (NIA AM-3) | Asset registry + EASM |

### 5. Buyer contracting checklist

- [ ] Ooredoo Cloud Business agreement signed
- [ ] Argus / Marsad reseller agreement signed
- [ ] Q-CERT NIA attestation obtained
- [ ] QCB notification (banking only)
- [ ] Penetration-test plan agreed
