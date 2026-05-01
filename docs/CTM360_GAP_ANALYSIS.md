# Argus vs CTM360 — Exhaustive Gap Analysis

**Date:** 2026-04-28
**Author:** Arjun (for Krishna)
**Repo audited:** `gaigenticai/argus` @ HEAD
**CTM360 surface mapped from:** ctm360.com homepage, datasheets index, DRP stack page

---

## 1. CTM360 Full Product Surface (master list)

### 1.1 Core Platforms (6)
| # | Platform | Function |
|---|----------|----------|
| P1 | **HackerView** | EASM + Security Ratings + External Exposure |
| P2 | **CyberBlindspot** | DRP + Targeted Threat Intel + Brand Protection + Takedowns |
| P3 | **ThreatCover** | CTI + Threat Actor Playbooks + Risk-based Hardening |
| P4 | **DMARC360** | DMARC implementation, optimization, RUA/RUF reporting |
| P5 | **RiskHub** | TPRM + Supply Chain + Vendor Questionnaires + Posture |
| P6 | **CyNA** | Cyber news, advisories, vulnerability feed, actor claim feed |

### 1.2 Specialized Modules / Capabilities (exhaustive)
| # | Module | Belongs to |
|---|--------|------------|
| M1 | External Attack Surface Management | HackerView |
| M2 | Security Rating Services (A–F grade) | HackerView |
| M3 | External Exposure Management (DeepScan) | HackerView |
| M4 | Surface Web Intelligence | CyberBlindspot |
| M5 | Deep Web Intelligence | CyberBlindspot |
| M6 | Dark Web Intelligence | CyberBlindspot |
| M7 | Brand Protection | CyberBlindspot |
| M8 | Anti-Phishing | CyberBlindspot |
| M9 | Phishing Site Detection (typosquat, lookalikes, homoglyph) | CyberBlindspot |
| M10 | Logo / Visual Brand Abuse Detection | CyberBlindspot |
| M11 | Social Media Fraud Monitoring | CyberBlindspot |
| M12 | Executive / VIP Impersonation Monitoring | CyberBlindspot |
| M13 | Online Anti-Fraud (investment scams, fake schemes) | CyberBlindspot |
| M14 | Domain Protection (newly registered, suspicious TLDs) | CyberBlindspot |
| M15 | Credit Card Leakage Monitoring | CyberBlindspot |
| M16 | Data Leakage Protection (DLP — external) | CyberBlindspot |
| M17 | Mobile App Store Monitoring (rogue apps) | CyberBlindspot |
| M18 | Threat Actor Playbooks (per-actor TTP profiles) | ThreatCover |
| M19 | Risk-based Hardening Guidelines | ThreatCover |
| M20 | MITRE ATT&CK mapping on every IOC/incident | ThreatCover |
| M21 | Threat Actor Claim Monitoring (leak-site scraping) | ThreatCover / CyNA |
| M22 | Cloud Threat Hunting | CyberBlindspot |
| M23 | DMARC Implementation Wizard | DMARC360 |
| M24 | DMARC Optimization Engine | DMARC360 |
| M25 | DMARC RUA/RUF Report Ingestion + Parsing | DMARC360 |
| M26 | Email Sending Trends Analysis | DMARC360 |
| M27 | SPF/DKIM Validation & Monitoring | DMARC360 |
| M28 | Third-Party Risk Management | RiskHub |
| M29 | Supply Chain Risk Monitoring | RiskHub |
| M30 | External Security Posture Mgmt (ESPM) | RiskHub |
| M31 | Security Assessment Questionnaires | RiskHub |
| M32 | Vendor Onboarding Workflow | RiskHub |
| M33 | Global Cyber News Feed | CyNA |
| M34 | Vulnerability Feed | CyNA |
| M35 | CTM360 Reports & Advisories | CyNA |
| M36 | Issue Management & Remediation Workflow | Cross-platform |
| M37 | 24/7 CIRT (managed) | Service |
| M38 | Unlimited Managed Takedowns (registrar/host/social) | Service |
| M39 | Global Threat Disruption | Service |
| M40 | API & Escalation Services | Service |
| M41 | Community Edition (free SME tier) | Platform |

### 1.3 CTM360 Operational Moat (NOT a software gap)
- ICANN-recognised takedown ops
- Pre-existing legal escalation channels with Apple App Store, Google Play, Meta, X/Twitter, LinkedIn, Telegram, Discord
- 24/7 SOC staffed in Bahrain
- 10+ years of registrar/host accreditation

---

## 2. Argus Current Inventory (verified by audit)

### 2.1 Modules present
| Layer | Implemented |
|-------|-------------|
| **Crawlers** | Tor (`tor_crawler`), I2P, Lokinet, Matrix, Telegram, ransomware leak sites, stealer logs, generic forums |
| **Feeds** | KEV, OTX (AlienVault), GreyNoise, phishing, malware, botnet, ransomware, SSL, IP reputation, honeypot, Tor nodes, geolocation |
| **Enrichment** | IOC extractor, PII detector, credential checker, actor tracker, surface scanner |
| **Agents (LLM)** | Triage, correlation, feed triage |
| **Integrations** | Suricata, Wazuh, OpenCTI, Spiderfoot, Nuclei, Prowler, YARA, Sigma, Gophish, Shuffle |
| **API routes** | activity, actors, alerts, audit, auth, crawlers, feedback, feeds, integrations, iocs, organizations, reports, retention, scan, sources, stix, threat_map, users, webhooks |
| **Dashboard pages** | organizations, settings, crawlers, activity, surface, feeds, alerts, integrations, actors, sources, iocs, threat-map, notifications, login, reports |
| **Storage** | PostgreSQL + pgvector, Redis Streams, Meilisearch |
| **Deployment** | Docker Compose + K8s, fully self-hosted, Ollama support |
| **MITRE ATT&CK** | Partially wired (correlation_agent, stealer_crawler, intel model, report_generator reference it — not yet a first-class taxonomy across all alerts) |

---

## 3. THE GAP TABLE — every CTM360 capability mapped to Argus

Legend: ✅ present · 🟡 partial · ❌ missing · 🚫 service-not-software

| # | CTM360 Capability | Argus Status | Notes / What's needed |
|---|---|---|---|
| M1 | EASM (continuous external asset discovery) | 🟡 | Has `surface_scanner` + `scan` route. Missing: continuous discovery loop, asset inventory model w/ ownership, change detection, dashboard view of "attack surface" as first-class object |
| M2 | Security Ratings (A–F external grade) | ❌ | Need scoring engine: weight EASM signals (open ports, expired certs, vuln versions, DMARC, breaches) → letter grade |
| M3 | External Exposure Management (DeepScan) | 🟡 | Have Nuclei integration; missing scheduled DeepScan profile + scoped exposure dashboards |
| M4 | Surface web intel | ✅ | Covered by feeds + crawlers |
| M5 | Deep web intel | ✅ | Forum + paste crawlers |
| M6 | Dark web intel | ✅ | **Stronger than CTM360** — also covers I2P, Lokinet, Matrix |
| M7 | Brand Protection (umbrella) | ❌ | Need brand asset registry + monitoring pipeline |
| M8 | Anti-phishing detection (live phishing kit / page) | 🟡 | Phishing feed ingested, but no proactive crawler that fetches+classifies suspect domains |
| M9 | Typosquat / lookalike / homoglyph domain detection | ❌ | Need: CertStream (CT log) ingest + dnstwist-style permutations + scoring |
| M10 | Logo / visual brand abuse | ❌ | Need: CLIP/OpenCLIP embeddings → similarity search vs registered logos |
| M11 | Social media fraud monitoring | ❌ | Need scrapers: X/Twitter, Meta, LinkedIn, TikTok, YouTube, Telegram public, Discord public |
| M12 | Executive / VIP impersonation | ❌ | Need: VIP registry, face-similarity (InsightFace OSS), bio/handle fuzzy match |
| M13 | Online anti-fraud (investment scams) | ❌ | Need scam-keyword classifier + crypto wallet/Telegram channel watcher |
| M14 | Domain Protection (newly-registered, suspicious TLDs) | ❌ | Need WHOIS/RDAP feed + newly-registered domain list (whoisds, dnpedia OSS) |
| M15 | Credit card leakage | 🟡 | Stealer crawler exists; missing CC-specific BIN-aware extractor + bank ownership match |
| M16 | External DLP (sensitive doc/keyword leakage) | 🟡 | PII detector exists; missing customer-keyword/regex policy engine + paste-site coverage |
| M17 | Mobile app store rogue app monitoring | ❌ | Need: Apple App Store + Google Play scrapers (OSS: `google-play-scraper`, `app-store-scraper`) + brand match |
| M18 | Threat actor playbooks (per-actor TTPs) | 🟡 | `actors` route exists; missing structured TTP profile, victim list, infra IOCs per actor |
| M19 | Risk-based hardening guidelines (auto-generated) | ❌ | Need: agent that maps detected exposure → CIS/NIST control recommendations |
| M20 | MITRE ATT&CK first-class | 🟡 | Referenced in 6 files; not enforced on every alert/IOC. Need ATT&CK taxonomy table + tagging pipeline |
| M21 | Ransomware leak-site claim monitoring | ✅ | `ransomware_crawler` covers it |
| M22 | Cloud threat hunting | 🟡 | Prowler integration covers AWS/Azure/GCP misconfig; missing hunt-query library + scheduled runs |
| M23 | DMARC implementation wizard | ❌ | Need UI flow to generate SPF/DKIM/DMARC records |
| M24 | DMARC optimization engine | ❌ | Need analyzer that recommends p=quarantine→reject progression |
| M25 | DMARC RUA/RUF report ingestion | ❌ | Need: SMTP receiver / mailbox poller + XML parser (OSS: `parsedmarc`) |
| M26 | Email sending trends | ❌ | Aggregated charts on top of M25 |
| M27 | SPF/DKIM live validation | ❌ | Need DNS lookup + alignment checker |
| M28 | TPRM (third-party risk) | ❌ | Need vendor model, questionnaire engine, scorecard |
| M29 | Supply chain risk monitoring | ❌ | Need vendor-domain EASM + breach monitoring |
| M30 | External Security Posture Mgmt | ❌ | Roll-up of EASM + DMARC + Ratings into vendor-or-self view |
| M31 | Security assessment questionnaires (SIG, CAIQ, custom) | ❌ | Need form builder + scoring + evidence upload |
| M32 | Vendor onboarding workflow | ❌ | Need workflow engine (can reuse Shuffle integration as substrate) |
| M33 | Global cyber news feed | ❌ | Need RSS aggregator + LLM relevance scoring (OSS: `feedparser`) |
| M34 | Vulnerability feed (curated) | 🟡 | KEV present; missing NVD full mirror + EPSS scoring (OSS: NVD JSON, FIRST EPSS) |
| M35 | Custom advisories (vendor reports) | ❌ | Need editorial/publishing module |
| M36 | Issue management workflow | 🟡 | Alerts exist; missing ticket-grade lifecycle (open→acknowledged→remediated→verified→closed) + SLA |
| M37 | 24/7 CIRT (managed service) | 🚫 | Service offering — we'd need to staff or partner |
| M38 | Unlimited Takedowns | 🚫 | **Operational moat** — no OSS substitute; partner with Netcraft/PhishLabs OR build registrar relationships |
| M39 | Global Threat Disruption (proactive sinkhole, takeover) | 🚫 | Requires legal accreditation |
| M40 | Public API & escalation | 🟡 | API exists; missing rate-limited public API tier + escalation webhooks to phone/SMS |
| M41 | Community Edition (free tier) | ❌ | Need stripped-down Docker image + signup flow (good marketing play given OSS posture) |

### 3.1 Cross-cutting gaps not tied to a single module
| # | Gap | Impact |
|---|-----|--------|
| X1 | **Unified asset registry** — domains, IPs, executives, brands, mobile apps, social handles, vendors as first-class entities owned by a tenant | Foundational; everything M1–M32 depends on it |
| X2 | **Customer onboarding wizard** — currently no "tell us your domains, executives, brands, vendors" flow | Blocks demo readiness |
| X3 | **Evidence vault** — screenshots, page HTML, WHOIS history, takedown proof | Required for M7–M14, M38 |
| X4 | **Case management** — group findings into a case, assign analyst, audit trail | Required for SOC workflows |
| X5 | **Notification routing** — email/Slack/Teams/SMS/webhook with severity-based escalation | Partial (webhooks route exists) |
| X6 | **SLA + reporting** — exec PDF reports, monthly KPI digest | Partial (`reports` route exists, content unclear) |
| X7 | **Public-tier sandbox / Community Edition** | Marketing-driven, M41 |
| X8 | **Multi-tenant data isolation review** — tenants exist, need verification of row-level security on every model | Compliance / bank-grade requirement |
| X9 | **Compliance certifications** — SOC2, ISO 27001 trail (out of code, but doc + audit hooks needed) | Sales blocker for enterprise |

---

## 4. OSS-First Recommended Tooling (per gap)

| Gap | OSS components to use |
|-----|------------------------|
| M1 EASM continuous | **OWASP Amass**, **Subfinder**, **httpx**, **naabu** (ProjectDiscovery suite, all OSS/MIT) |
| M2 Security Rating | Custom scoring on top of EASM signals — no OSS clone needed |
| M3 DeepScan | **Nuclei** (already integrated), **Nmap**, **OpenVAS/Greenbone** |
| M9 Typosquat | **dnstwist** (MIT), **CertStream** Python client, **whoisds** newly-registered list |
| M10 Logo abuse | **OpenCLIP** (MIT), **FAISS** for similarity index |
| M11 Social scraping | **snscrape** (Twitter/X), **instaloader**, **TikTok-Api**, **Telethon**, **discord.py** — all OSS |
| M12 Face similarity | **InsightFace** (MIT), **face_recognition** (dlib) |
| M14 Newly-registered domains | **whoisds.com** daily list (free), **CertStream**, **OpenSquat** (GPL) |
| M17 App store | **google-play-scraper** (MIT), **app-store-scraper** (MIT) |
| M19 Hardening guidelines | Map exposure to **CIS Controls v8** + **MITRE D3FEND** (open) |
| M20 MITRE ATT&CK | **STIX2 / mitreattack-python** (Apache 2.0) |
| M22 Cloud hunting | **Prowler** (already integrated), **CloudSploit/Aqua Trivy**, **Stratus Red Team** |
| M23–M27 DMARC | **parsedmarc** (Apache 2.0), **OpenDMARC**, custom DNS validators with **dnspython** |
| M28–M32 TPRM | Build on **Eramba** (GPL — careful, copyleft) OR build native; questionnaire = simple Postgres + Next.js form engine |
| M33 News | **feedparser**, OTX RSS, US-CERT, CISA RSS, vendor feeds |
| M34 Vuln feed | **NVD JSON 2.0 mirror**, **EPSS** scores from FIRST, **CVE-Search** (GPL) |
| M36 Issue workflow | **Plane** (AGPL) or build native with FastAPI |
| M38 Takedown (partner) | API integrations — **Netcraft**, **PhishLabs**, **Group-IB**; OR use **abuse.ch** community channels for free disruption |
| Evidence vault | **MinIO** (AGPL — fine for self-hosted) or filesystem |

**⚠️ License watch:** AGPL/GPL items above (Eramba, Plane, OpenSquat, MinIO, CVE-Search) — fine for self-hosted single-tenant per customer; **must isolate from Argus core if Argus is ever offered as SaaS** to avoid copyleft contamination. Prefer MIT/Apache where possible.

---

## 5. Honest Answer: Can we actually match CTM360 (excluding takedown moat)?

**Yes — in software, fully. In services, partially. Here's the breakdown:**

### 5.1 What we can match 1:1 (software gaps)
All of M1–M36 are buildable with OSS components. None of them require novel research — they're well-trodden. Realistic engineering effort with one focused team:

| Tier | Modules | Effort |
|------|---------|--------|
| **Quick wins (3–4 wks)** | M9, M14, M20, M23–M27, M33, M34 | Pure plumbing |
| **Medium (4–6 wks)** | M1 productized, M2, M3, M8, M17, M18, M19, M22, M36, X1–X4 | Mostly UX + scoring + workflow |
| **Heavy (6–10 wks)** | M7+M10, M11, M12, M13, M15, M16, M28–M32 | Scrapers + ML + GRC engine |

**Total realistic delivery to feature-parity software:** **~14–18 weeks** with 2 strong engineers + you. Compressible to 10–12 weeks if we drop polish for the lead demo.

### 5.2 What we can match with effort but not equivalence
| Capability | Us | Why not equivalent |
|-----------|-----|---------------------|
| M37 24/7 CIRT | Hire 3-shift SOC OR partner with regional MSSP | They have 10 yrs of muscle memory, runbooks, escalation patterns |
| M40 Escalation services | Build via Twilio/PagerDuty | Easy technically; trust takes time |

### 5.3 What we **cannot** match in <12 months
| Capability | Why |
|-----------|-----|
| M38 Unlimited Takedowns | Requires registrar/host/platform legal relationships built over years |
| M39 Global Threat Disruption | Requires sinkhole authority, court orders, ICANN standing |
| Brand recognition in GCC banking | Their 10-year head start |

### 5.4 Where we beat them — leverage hard
1. **Self-hosted / data sovereignty** — they're Bahrain SaaS, we run in customer VPC. **Banks in EU/India/sanctioned jurisdictions cannot legally use CTM360.** This is a buyer's veto-level advantage.
2. **Open source** — auditable code, no vendor lock-in. Banks love this for procurement.
3. **Agentic LLM triage** — they're rules-heavy. Our triage agent + correlation agent are next-gen.
4. **Broader dark web** — I2P, Lokinet, Matrix coverage they don't advertise.
5. **Docker-first deployment** — matches GaigenticOS doctrine, lets us bundle.
6. **Cost** — OSS stack + self-hosted = we can undercut their pricing 50%+ and still have margin.

### 5.5 Bottom line for the lead

**Honest pitch to the customer:**
> "We match every software capability of CTM360, deployed inside your perimeter with full source-code transparency, with agentic AI on top. For takedowns we partner with [Netcraft/regional vendor] and bundle it as 'unlimited managed takedowns' identical commercial terms. For 24/7 SOC, we offer [our staffed option / regional MSSP partnership]. You get sovereignty, lower cost, and a roadmap you control."

**Do not lie about takedown ownership.** Banks will check. Be upfront — partner is fine, fake is fatal.

**My recommendation:** Yes, take the lead. Scope the demo to Phase-1 quick wins (DMARC + typosquat + brand monitor + MITRE tagging + Security Rating) which is **3–4 weeks to a credible demo**. Sign with a Phase-2/3 roadmap commitment. Use the customer revenue to fund Phases 2 & 3.

---

## 6. Deal-breakers / things I need from you to proceed

1. **Confirm OSS-only constraint** — does it block AGPL components used as separate services (MinIO, Plane)? My read: AGPL-as-isolated-service is fine for our doctrine. Confirm.
2. **Takedown partner** — pick one (Netcraft / PhishLabs / regional). Without this the pitch has a hole.
3. **Lead context** — sector (bank/govt/telecom?), region, and what specifically attracted them. Lets me tune the demo modules to their pain.
4. **Argus license** — README says proprietary. If we're "open source first", we need to flip Argus to AGPL or Apache 2.0 publicly. **Decision needed before pitching OSS posture.**
5. **Engineering capacity** — am I working solo on this, or do I get help? Affects timeline honesty.

---

*End of gap analysis. No capability omitted. Every OSS substitute named. Every license risk flagged.*
