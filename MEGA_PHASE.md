# MEGA_PHASE.md — Argus Path-to-King Roadmap

**Status:** Plan, awaiting build approval per phase.
**Owner:** Krishna / Gaigentic AI.
**Audience:** internal eng + commercial.
**Source:** synthesised from a 4-agent research pass on (1) commercially-licensable TI feeds, (2) OSS analysis/enrichment platforms, (3) GCC/ME threat landscape & regulation, (4) audit of current Argus capabilities + dealbreaker gaps.
**Last updated:** 2026-05-01.

> **Vision.** Argus becomes the **open-standards, executable-intel, GCC-compliant** alternative to Recorded Future / Mandiant / KELA — sold first to Middle East banks, oil & gas, telcos, and government via warm SI introductions, then rolled out global. Differentiator: customers stop being feed-locked, alerts ship as running detections (not PDFs), and we deploy in-region with native NCA / SAMA / NESA evidence packs no US incumbent can answer in <18 months.

---

## 0. How to read this document

- Three implementation phases (🟢 / 🟡 / 🔴) sized in calendar-weeks of focused engineering.
- Every dealbreaker gap, every "demolish RF/Mandiant" promise, every shortlist feed appears in exactly one phase.
- Effort estimates are days of single-engineer focus; double for parallel polish.
- All third-party feeds and OSS tools listed have been licence-checked at headline level — but **must be re-verified by legal** before each one is wired into a paying-customer install. Free-tier-for-personal-use is a hard NO for a commercial SaaS.
- Each phase has a "Definition of Done" so we know when to ship.

---

## 1. Where Argus stands today (audit baseline)

### 1.1 Already shipped

| Pillar | Capability |
|---|---|
| **Crawlers** | Tor, I2P, Lokinet forum + marketplace, Telegram, Matrix, ransomware leak-site, stealer market — 9 active classes |
| **Feeds (live)** | NVD, EPSS, CISA KEV, OTX, GreyNoise, AbuseIPDB, abuse.ch (URLhaus / ThreatFox / Feodo), Cloudflare Radar, BGPstream, MaxMind GeoLite2 (in-progress), MITRE ATT&CK STIX |
| **Agentic surface** | 6 agents — `triage`, `brand_defender`, `case_copilot`, `threat_hunter`, `investigation`, `correlation`. Tool-calling on Anthropic native; JSON-prompt fallback on Ollama/OpenAI/Bridge |
| **Models / data** | 73 SQLAlchemy tables across alerts, IOCs, threat-actors, brand, social, leakage, exposures, evidence, cases, TPRM, MITRE, retention, audit |
| **API surface** | 25+ FastAPI route modules; auth via JWT + API keys; **TAXII 2.1 read-only server** exposing indicators / threat-actors / alerts collections |
| **Dashboard** | 42 Next.js routes covering every domain; AppShell + sidebar nav; clickable KPI tiles; themed `<Select>` everywhere (no native popups) |
| **Reports** | `reportlab` PDF executive briefs (cover, charts, tables, severity breakdowns) |
| **Ops** | Docker compose stack, retention policies, legal hold flags on cases + audit, SLA breach engine, feed-health monitor, audit log, host-native Claude Code bridge for LLM |
| **Demo content** | 3 industry orgs + Argus Demo Bank, ~27 alerts, 8 threat actors, 30+ IOCs, 16 cases, 24 evidence blobs, 21 exposures, 15 suspect domains — all FK-correct, idempotent across re-seeds |
| **LLM provider abstraction** | Bridge / Anthropic native / OpenAI / Ollama (4 providers, switchable via `ARGUS_LLM_PROVIDER`) |

### 1.2 Stubs / shells already present (low-friction integrations)

OpenCTI · SpiderFoot · YARA · Sigma · Suricata · Wazuh · Nuclei · Prowler · GoPhish · Shuffle.

These directories exist with `__init__.py` and config wiring; the runtime code is partial. Each gets called out below where it slots into a phase.

### 1.3 Honest dealbreaker gap list (from CISO-buyer perspective)

| Gap | % CISOs flag | Rough effort | Phase |
|---|---|---|---|
| SIEM connectors (Splunk HEC, Sentinel, Elastic, QRadar) | 80 % | 5d × 4 | 🟡 P2 |
| Multi-tenant / MSSP isolation | 80 % | 10–15d | 🔴 P3 |
| EDR connectors (CrowdStrike, SentinelOne, Defender) | 75 % | 8d × 3 | 🔴 P3 |
| Email gateway (Proofpoint TAP, Mimecast, Abnormal) | 72 % | 4d × 3 | 🔴 P3 |
| Sandbox (CAPE, Joe, Hybrid-Analysis, VT BYOK) | 70 % | 4d × N | 🔴 P3 |
| Knowledge graph (OpenCTI / STIX-native) | 65 % | 10–15d | 🟡 P2 |
| Customer-facing API + Python/JS SDK + TAXII publish | 65 % | 7–10d | 🔴 P3 |
| Threat-actor attribution scoring (confidence-weighted) | 55 % | 3–4d | 🟡 P2 |
| Compliance auto-mapping (NIST CSF / ISO 27001 / PCI 4.0 / NCA-ECC / NESA) | 50 % | 8–12d | 🟢 P1 |

---

## 2. Middle East market context (informs every phase)

### 2.1 Top regional threat-actor cluster (active 2024–2026)

| Actor | Aliases | Affiliation | Targets | Headline TTPs |
|---|---|---|---|---|
| APT33 | Elfin, Refined Kitten, Holmium, Peach Sandstorm | IRGC | KSA/UAE aviation, petrochemical, defense | DropShot/Shapeshift wipers, password spray T1110.003, hybrid-identity |
| APT34 | OilRig, Helix Kitten, Hazel Sandstorm | MOIS | GCC gov, finance, energy, telco | DNS tunneling T1071.004, SideTwist, Saitama, Outer Space, Juicy Mix |
| APT35 | Charming Kitten, Mint Sandstorm, TA453 | IRGC-IO | Officials, journalists, dissidents, academics | MFA-fatigue T1621, GhostEcho/POWERSTAR, fake conference invites |
| APT39 | Chafer, Remix Kitten | MOIS-ITSec | Telco, travel, comms, GCC + Turkey | ASPXSpy webshells, Remexi backdoor, RDP pivot |
| MuddyWater | Static Kitten, Mango Sandstorm, Seedworm | MOIS | Gov, NGO, telco, oil — KSA, UAE, Jordan, Iraq | LIGOLO, PhonyC2, Atera/SimpleHelp/ScreenConnect RMM abuse T1219 |
| DEV-0270 | Cobalt Mirage, Nemesis Kitten | IRGC affiliate | Opportunistic ransomware GCC + US/Israel | BitLocker abuse T1486, Fast Reverse Proxy, Log4Shell |
| Imperial Kitten / Agrius / Moses Staff / Karma | DEV-0227 | Iran-aligned destructive | Israel + GCC supply chain | Wipers as fake ransomware (Apostle, DEADWOOD, IPsec Helper) |
| Cyber Av3ngers | — | IRGC-linked OT | OT/ICS in water, energy, manufacturing | OT bragging on Telegram, named-victim exfil claims |
| Lazarus / APT38 / BlueNoroff | DPRK-Lazarus | DPRK | Banks (SWIFT), ATMs, crypto exchanges | TraderTraitor / AppleJeus, LinkedIn job-lure T1566.003 |
| LockBit-successor cluster | RansomHub, Akira, Play, Qilin, BlackSuit, 8Base, Hunters International, INC | Mixed | GCC mid-market manufacturing, logistics, healthcare | Affiliate-driven; track DLS for `.sa/.ae/.qa/.kw/.bh/.om/.eg` victims |
| Anonymous Sudan (post-Oct-2024 indictment) | Skynet/Godzilla botnet | RU-aligned hacktivist | UAE / KSA / Israeli infra DDoS | Booter-as-a-service; copycats persist after principals indicted |
| Arabic-speaking IABs | — | Underground | Initial access broker; sells RDP/VPN access | Listings on XSS, Exploit, BreachForums-successors |
| BEC + carding (Scattered-Spider-style + Arabic clusters) | UNF / Octo Tempest | Mixed | GCC freight forwarders, real estate, Hawala | SIM-swap on Etisalat / STC / Ooredoo |
| Insider threat (GCC O&G specific) | n/a | Local | Aramco/ADNOC/QatarEnergy | USB sneakernet (OT air-gap), shared SCADA accounts, WhatsApp/Telegram exfil of drawings, post-employment recruiting |

### 2.2 Regulatory frameworks Argus must auto-map findings to

| Country | Framework(s) | What Argus must produce |
|---|---|---|
| 🇸🇦 KSA | NCA ECC-1:2018 / ECC-2:2024, NCA CCC (Cloud), DCC (Data), CSCC (Critical Systems), SAMA Cyber Security Framework v1.0, SAMA Counter-Fraud Framework | Tagged IOCs/findings by ECC control ID; auditor evidence packs; Arabic exec reports; KSA data-residency attestation; SAMA monthly threat reports + peer-bank typology sharing |
| 🇦🇪 UAE | NESA / TDRA UAE-IAS (under UAE CSC), ADHICS v2 (Abu Dhabi healthcare), SIA CIIP | Mappings to T1.5.x (Threat & Vulnerability Mgmt); PHI-aware redaction in leak monitoring; sector-tier reporting cadences |
| 🇶🇦 Qatar | NCSA NCSF 2022, NIA Policy v2.2, QCERT | Tier-aware controls (C1–C4); STIX/TAXII export to QCERT |
| 🇧🇭 Bahrain | CBB Cybersecurity Module, PDPL 2018 | 72hr breach-notice timelines; lawful-basis tagging on PII surfaced in leaks |
| 🇰🇼 Kuwait | CITRA cybersecurity, KCERT | Sectoral advisory templates |
| 🇴🇲 Oman | OCERT | Sectoral advisory templates |
| 🇪🇬 Egypt | NTRA cybersecurity directives, Data Protection Law 151/2020 | Telco emphasis; cross-border transfer flags |
| 🇮🇱 Israel | INCD Cyber Defense Methodology 2.0 | Likely deprioritized for v1 GTM (political sensitivity vs KSA/UAE simultaneous selling) |
| 🌐 Universal | PCI-DSS 4.0.1 (effective Mar 2025), ISO 27001:2022 (Annex A.5.7 explicit TI control), NIST CSF 2.0, SOC 2 CC7.3 | Single "Compliance Evidence Pack" exporter |

**Key feature spec:** A single **per-tenant Compliance Evidence Pack** export that re-tags every alert / IOC / hardening recommendation with the relevant control IDs across whichever frameworks the tenant has enabled. This is the most sellable feature for GCC compliance buyers.

### 2.3 Localization requirements

> **Decision (2026-05-01):** Argus UI ships **English-only**. Arabic UI translation has been **deliberately removed** from scope. English is the working language of GCC SOCs (Splunk, CrowdStrike, Sentinel, MISP, Recorded Future, Mandiant all ship English-only into GCC and win deals). Translating cybersecurity vocabulary ("phishing", "ransomware", "T1566.001", "C2", "TLP:RED") would make the product worse and impose a permanent ~30 % drag on every shipped feature. The handful of buyers who genuinely need Arabic UI can use browser auto-translate (Edge / Chrome built-in). What we DO ship instead are the four content/data features below.

What we **keep / add** for ME flavour (no UI translation overhead):

- **Time zones** — default tenant TZ to `Asia/Riyadh` (UTC+3) or `Asia/Dubai` (UTC+4). Cron triggers + alert timestamps + scheduled reports all respect it.
- **Calendars** — Hijri display alongside Gregorian on compliance reports & evidence packs. `umalqura` calendar (Saudi official).
- **Bilingual Compliance Evidence Pack** — when exporting for a regulator-facing audience the operator can toggle "Bilingual"; the cover + executive-summary section render in Arabic, the technical body stays English. (Cheaper + more useful than a fully translated UI.)
- **Arabic / Persian / Farsi NLP in the crawler & enrichment pipeline** — CAMeL Tools / AraBERT for Arabic; separate Farsi model for IRGC/MOIS forum content. Dialects matter: MSA vs Gulf vs Levantine vs Egyptian — leak chatter is rarely MSA. **This is data, not UI** — required for source coverage regardless of UI language.
- **Char-level Arabic phishing detection** — Arabic-Indic digits, Latin look-alikes (ل/l, ٥/5), RTL-override (U+202E) abuse, mixed-script Arabic IDN domains.
- **Seed pretexts** for the phishing detector — Hajj/Umrah visa & accommodation, Absher / Tawakkalna / TAM / ICA UAE, Aramco/ADNOC/QatarEnergy bonus & payslip, Etihad/Emirates/flydubai/Saudia refund, MoF/ZATCA tax refund, Saned/GOSI/TASI subsidy, Ramadan e-card, UAE Pass/Nafath OTP, electricity (SEC/DEWA/EWA) bill, Salik/Darb toll, traffic-fine (Muroor/Saher).
- **RTL-safe rendering of user content** — alert summaries / leak excerpts / phishing email bodies that *contain* Arabic text render with `dir="auto"` so Arabic content displays right-to-left without a full UI flip.

### 2.4 Regional sources & forums to crawl

- **Arabic underground forums** — historical roots in dev-point, v4-team, sec4ever, arabhackers (mostly defunct or low-signal); chatter migrated to Telegram + Discord. `0x00sec.ar` *(unverified, treat as draft)*.
- **Telegram clusters** — Arabic-language carding/CC sharing; "leaks" channels reposting from BreachForums-successors; hacktivist channels (pro-Palestine ops, Yemeni Cyber Army, Cyber Av3ngers/IRGC-linked OT bragging); Iranian-linked "leak X bank" channels post-2023 Israeli bank/insurer dumps.
- **Iranian leak channels** — Cyber Av3ngers, Handala, Karma, Moses Staff/Abraham's Ax, Soldiers of Solomon (claim GCC/Israeli victim data).
- **Ransomware leak sites — GCC pattern** — RansomHub, Akira, Play, Qilin, LockBit-revival, Hunters International, BlackSuit, INC Ransom — filter for `.sa/.ae/.qa/.kw/.bh/.om/.eg`, Arabic company names, parent-company structures.
- **X / Twitter Arabic OSINT** — `#اختراق #تسريب #هاكر #اخبار_الامن_السيبراني` (high-noise; early-warning trigger only).
- **LinkedIn Arabic CISO community** — sales intel + impersonation/exec-spoof detection (clone profiles of GCC CISOs are common).
- **Government feeds** — Saudi NCA advisories, HE-CERT (Haiah), CERT.ae, Q-CERT, BH-CERT, KCERT, OCERT, EG-CERT — most publish PDFs, some STIX.

### 2.5 Competitive landscape (rough mindshare ranking in GCC)

| # | Vendor | Pricing band (USD/yr) | Strength | Weakness Argus exploits |
|---|---|---|---|---|
| 1 | Recorded Future | $150K – $500K+ | Incumbent at large GCC banks/gov | Shallow Arabic; no per-tenant residency; no compliance evidence packs |
| 2 | Group-IB | $80K – $300K | Dubai HQ, fraud + CERT-side strong | Geopolitical sensitivity in some deals |
| 3 | Mandiant (Google Cloud) | $200K – $1M+ (often w/ IR retainer) | APT attribution credibility | US-SaaS only; charges $400/hr for hunt queries |
| 4 | KELA | $60K – $200K | Deep- / dark-web specialist | Israeli origin → friction in some KSA / Qatar deals |
| 5 | Cyberint (Check Point) | $50K – $150K | Digital risk + EASM | Same Israeli-origin caveat |
| 6 | Resecurity | $40K – $150K | Aggressive in GCC sales | Sometimes underestimated technically |
| 7 | CrowdStrike Falcon Intelligence | bundled w/ EDR | Strong attribution, SOC integration | Only relevant where Falcon EDR already deployed |
| 8 | ZeroFox | $40K – $120K | Brand / exec protection lean | Narrow scope — feature-only |

(Pricing directional from pre-2025 channel chatter; Krishna's brother to confirm in-region.)

### 2.6 Channel partners (warm intros via brother)

| Partner | Country | Strength |
|---|---|---|
| **Spire Solutions** | UAE (Dubai) | Strongest TI/security distributor in GCC; carries multiple TI vendors |
| **Help AG** (e& enterprise) | UAE | UAE MSSP heavyweight |
| **GBM** (Gulf Business Machines) | Multi-GCC | IBM-aligned, broad GCC footprint |
| **Mannai ICT** | Qatar | Qatar gov/enterprise |
| **Sirar by stc** | KSA | STC enterprise security arm |
| **SITE / Salam** | KSA | Saudi gov & enterprise |
| **CPX (ex-DarkMatter assets)** | UAE | UAE government & defence |
| **Injazat (e&)** | UAE | UAE enterprise & gov |
| **Paramount Computer Systems** | KSA / UAE / wider | Banking-leaning SI |
| **Beyontec & Beyontrust resellers** | UAE | Financial services |

---

## 3. The three things that **demolish** RF / Mandiant

These three claims must be true at the end of Phase 2 — they are the core sales narrative.

### 3.1 Open standards in *and* out
TAXII2 ingest **and** publish, STIX2 export, OpenCTI graph projection, Kestrel hunt language, Sigma rule generation, OSCAL control catalogue. Customers stop being feed-locked. RF/Mandiant deliberately don't expose this.

### 3.2 Executable intel, not PDFs
Every alert ships with: an auto-generated Sigma rule + a Kestrel hunt translated to the customer's actual SIEM (Splunk SPL / Sentinel KQL / Elastic ES|QL / QRadar AQL via STIX-Shifter) + a YARA/yara-x rule + a Velociraptor artifact + an ATT&CK Navigator layer JSON. **Mandiant ships a 40-page report; Argus ships running detections.**

### 3.3 In-region single-tenant + native GCC compliance
Sovereign deployment on KSA STC Cloud / UAE Core42 / Khazna *plus* native NCA-ECC / SAMA-CSF / NESA / ADHICS / Qatar NCSF control mapping. **No US-SaaS incumbent can answer this in <18 months.** Auto-tag every finding with the relevant control IDs; export per-framework Compliance Evidence Pack.

---

## 4. PHASE 1 — 🟢 Lethal in GCC (~2 weeks)

**Theme:** Walk-in demos that close ME deals on first meeting.

**Target buyer reaction:** "I've never seen a vendor demo Arabic-tagged dark-web leaks against my BIN ranges with a one-click NCA-ECC evidence pack. Send me a quote."

### Items

| # | Item | Effort | Rationale |
|---|---|---|---|
| 1.1 | **~~Arabic UI + RTL~~** — REMOVED 2026-05-01. UI ships English-only (see §2.3 decision). Replaced by the four small content/data features below. | 0d | English is GCC SOC working language; saves 5d + permanent maintenance tax. |
| 1.2 | **Hijri / Gregorian dual-date** + **Asia/Riyadh** default TZ (cron triggers respect). RTL-safe rendering of user-content via `dir="auto"`. | 1d | Compliance reports cite Hijri dates in Saudi; minimal effort. |
| 1.3 | ✅ **SHIPPED 2026-05-01** — Compliance Evidence Pack exporter with OSCAL backbone. 12 frameworks ship (NCA-ECC v2, SAMA-CSF v1, ISO 27001:2022 Annex A subset, NIST CSF 2.0, NESA/TDRA v2, ADHICS v2, Qatar NIA v2, Bahrain CBB OM-7, Kuwait CITRA, Oman NISF, PCI-DSS 4.0.1, SOC 2 CC7) — 97 controls, 295 signal-to-control mappings. Per-tenant framework selector + bilingual toggle (Arabic exec-summary + English technical body) live. 8 integration tests passing. | 8d | The single most sellable feature for GCC compliance buyers. |
| 1.4 | ✅ **SHIPPED 2026-05-01** — Iran-APT TTP overlay. Six curated actor profiles (APT33 / APT34 / APT35 / MuddyWater / DEV-0270 / Cyber Av3ngers) seeded into `threat_actors`. Auto-apply hook in `actor_tracker.py` attaches actor TTPs to any alert linked via `ActorSighting`. Navigator v4.5 layer download at `GET /api/v1/actors/{id}/navigator-layer?matrix=enterprise|ics`. 5/5 integration tests passing. | 1d | "Show APT34 coverage on my estate" demo wow moment. |
| 1.5 | ✅ **SHIPPED 2026-05-01** — GCC ransomware DLS filter. Pure-function scorer over country code, ccTLD (`.sa/.ae/.qa/.kw/.bh/.om/.eg` + sub-levels), Arabic letters, and ~120 curated GCC brand/company keywords. Watchlist bump for the 8 named groups. Hooked into `src/feeds/ransomware_feed.py` so every victim record carries `feed_metadata.gcc_relevance`. 29 unit tests covering each signal independently + false-positive guards. | 1d | Regional victim awareness ahead of ransomware groups' own announcements. |
| 1.6 | **Arabic phishing pretext detector** — char-level homoglyph (Arabic-Indic digits, Latin look-alikes), RTL-override abuse, Arabic IDN mixed-script. Seeded pretexts: Hajj / Umrah, Absher / Tawakkalna / TAM / ICA, Aramco / ADNOC / QatarEnergy bonus, Etihad / Saudia / flydubai refund, ZATCA tax refund, GOSI / TASI subsidy, Ramadan e-card, UAE Pass / Nafath OTP, SEC / DEWA / EWA bills, Salik / Darb tolls, Saher / Muroor traffic fines. | 2d | Native ME flavour competitors don't have. |
| 1.7 | **Five commercial-licensable feeds** (parallel) — ~3d total: | 3d | High-yield, low-friction. Verify every ToS with legal before shipping. |
| | • CertStream firehose + crt.sh (typosquat backbone) | | |
| | • CIRCL OSINT MISP / TAXII2 (best free Iran-APT coverage) | | |
| | • PhishTank + CERT.PL (broaden phishing baseline) | | |
| | • GHSA + ExploitDB + Nuclei templates (vuln intel beyond NVD) | | |
| | • abuse.ch SSLBL / JA3 / JA4 fingerprints (TLS into existing `tls_fingerprint.py`) | | |
| 1.8 | **Bootstrap creds via env** ✅ already shipped (last sprint). Confirm Railway example uses these. | 0d | Already done. |
| 1.9 | **Demo-data top-up** ✅ already shipped (`scripts/_augment_demo_bank_alerts.py` integrated into seed pipeline). | 0d | Already done. |

### Phase 1 — Definition of Done

- A KSA SAMA-regulated bank CISO can be walked through, end-to-end in 15 min with no internal tooling and no manual SQL:
  - dashboard tenant timezone defaulted to `Asia/Riyadh`; report dates shown as Hijri + Gregorian
  - an Iranian APT34 alert, auto-tagged to MITRE T1071.004
  - **"Compliance Evidence Pack"** export covering NCA ECC, SAMA-CSF, ISO 27001 A.5.7 in PDF + JSON, with the **bilingual toggle** flipped to produce an Arabic exec-summary + English technical body
  - a GCC-DLS ransomware victim post auto-flagged via the `.sa/.ae/.qa/.kw/.bh/.om/.eg` filter
  - an Arabic Hajj-pretext phishing alert with character-level explanation (homoglyph + RTL-override) — alert body renders Arabic correctly via `dir="auto"`, even though the surrounding UI is English
- All five commercial-licensable feeds in P1 #1.7 health-green in the `Feed Health` panel.
- Tested on Argus's three industry-org demo seed (Meridian / NovaMed / Helios) plus Argus Demo Bank.

---

## 5. PHASE 2 — 🟡 Demolish RF / Mandiant on technical merit (~4 weeks)

**Theme:** Make a sophisticated SOC engineer pick Argus over a $500K/yr incumbent.

**Target buyer reaction:** "It exports STIX, the alert ships a Sigma rule, and the hunt query already runs on my Splunk. I don't need the 40-page Mandiant PDF."

### Items

| # | Item | Effort | Rationale |
|---|---|---|---|
| 2.1 | **OpenCTI integration** (Apache-2.0 graph) — wire the existing stub to a co-deployed OpenCTI; project Argus entities (alerts, IOCs, actors, cases) and relationships into OpenCTI; keep PostgreSQL as system-of-record; expose graph queries as a new `/graph/*` API; embed an OpenCTI graph view inside the dashboard. | 10d | Closes the knowledge-graph gap. RF charges $150K/yr for STIX export — we'd give it free. |
| 2.2 | **CISA Decider** — auto-map free-text alert / IOC content to ATT&CK technique IDs with confidence scores. Wire into `triage_agent` + `feed_triage`. | 3d | Every alert auto-tagged to ATT&CK. Top-3 strategic move per audit. |
| 2.3 | **pySigma** + **sigma-cli** — auto-generate Sigma rules per IOC / per technique attachment; convert to 25+ SIEM dialects (Splunk SPL, Sentinel KQL, Elastic ES|QL, QRadar AQL, Chronicle YARA-L, Sumo Logic, Devo, Arctic Wolf …). | 4d | "Executable intel" promise. |
| 2.4 | **Kestrel** threat-hunting DSL — embed `kestrel-lang` as a tool inside `threat_hunter_agent`; produce hunt scripts as artefacts on case timelines. | 4d | Mandiant charges $400/hr consulting; we ship the hunt itself. |
| 2.5 | **STIX-Shifter** — embed the IBM/OCA library; translate STIX patterns into customer's data-source query language for 35+ sources (Splunk, Elastic, Sentinel, QRadar, CrowdStrike Falcon Data Replicator, Carbon Black, Sysmon, Snowflake, BigQuery, …). | 3d | Pairs with Kestrel + Sigma. |
| 2.6 | **ATT&CK Navigator layer auto-generated per alert** — every alert detail page exports a Navigator layer JSON capturing matched techniques + actor TTPs; one-click "open in Navigator". | 2d | Visual proof of coverage; competitor parity. |
| 2.7 | **SIEM connectors** (4) | 10d | 80 % dealbreaker. |
| | • Splunk HEC (HTTP Event Collector) — push every alert/IOC + Sigma rule | | |
| | • Microsoft Sentinel webhook + Logs API + watchlist export | | |
| | • Elastic bulk-ingest + ECS-shaped events + watcher rule | | |
| | • IBM QRadar reference set + AQL via STIX-Shifter | | |
| 2.8 | **CIRCL hashlookup** + **CIRCL pDNS** + **CIRCL Passive SSL** — public/free APIs, attribution required; wire as enrichment provider on IOC detail pages and inside `investigation_agent`. | 3d | Cheap, free, ME-relevant (CIRCL has strong Iran-APT coverage). |
| 2.9 | **Threat-actor attribution scoring** — confidence-weighted; combine sighting freshness, IOC overlap, TTP-in-scope, infrastructure-cluster proximity. Add `actor_confidence` model + UI badge. | 4d | "85 % likely vs 40 % likely" — a CISO question RF answers poorly on niche actors. |
| 2.10 | **YARA → yara-x + capa** upgrade — replace existing YARA shell with the Rust yara-x (faster) + Mandiant capa (capability extraction); pull the **Loki / Thor Lite rule corpus** as ground-truth content. | 4d | Faster scans + replicated capability without bundling AGPL. |
| 2.11 | **MISP integration via PyMISP only** — call CIRCL public + customer-private MISP servers; don't bundle the AGPL server. | 3d | Sharing communities + galaxy clusters. |
| 2.12 | **MITRE D3FEND** + **MITRE OSCAL** — pull D3FEND defensive technique DB; map OSCAL machine-readable controls (NIST 800-53 / CSF 2.0 / ISO 27001 / PCI-DSS). | 3d | Backbone of compliance auto-mapping; underpins Phase 1 #1.3 with real data. |

### Phase 2 — Definition of Done

- Open the dashboard `/iocs/{id}` page → see an OpenCTI graph card, an auto-generated Sigma rule, a Kestrel hunt translated to Splunk SPL **and** Sentinel KQL, an ATT&CK Navigator layer JSON link, an attribution score per associated actor.
- Hit `/api/v1/integrations/splunk/test` from a customer's Splunk → events flow.
- Run a customer's MISP server → IOCs sync into Argus + Argus's IOCs publish back.
- All Phase 2 features are exposed via the existing dashboard pages (Alerts / IOCs / Threat Actors / Threat Hunter) — no separate "advanced" section.

---

## 6. PHASE 3 — 🔴 MSSP & enterprise wins (~5–8 weeks)

**Theme:** Win $500K+ contracts; channel through SI partners; serve regulated multi-tenant scenarios.

**Target buyer reaction:** "Spire / Help AG can resell this to my GCC customers as a managed service, with separate tenants per bank and a single OCC pane. Send me the channel agreement."

### Items

| # | Item | Effort | Rationale |
|---|---|---|---|
| 3.1 | **Multi-tenant / MSSP mode** — full org isolation across DB (RLS already partial — extend to every table), API (JWT audience + per-org scopes), Redis (namespaced keys), MinIO (bucket-per-tenant), Meilisearch (index-per-tenant). MSSP "super-tenant" view aggregates across child tenants. | 12d | 80 % dealbreaker for SI resale. |
| 3.2 | **EDR connectors** (3) | 15d | 75 % dealbreaker. |
| | • CrowdStrike Falcon — Falcon Data Replicator pull, Real-Time Response trigger, IOA upload | | |
| | • SentinelOne — Singularity API + Black-list IOC push | | |
| | • Microsoft Defender for Endpoint — Graph API + custom IoC blocking | | |
| 3.3 | **Email gateway connectors** (3) | 12d | 72 % dealbreaker. |
| | • Proofpoint TAP (Targeted Attack Protection) — URL/threat fetch, blocklist push | | |
| | • Mimecast — secure email gateway API + URL Protect lists | | |
| | • Abnormal Security — case enrichment + abuse-mailbox sync | | |
| 3.4 | **Customer-facing OpenAPI 3.1 schema** + **Python SDK** + **JS/TS SDK** + per-tenant TAXII publish (so the customer's downstream Splunk ES / Anomali / ThreatConnect can subscribe to *Argus-as-a-feed*). Per-user feed subscriptions + filter rules. | 8d | 65 % dealbreaker; TAXII publish alone is RF's $150K/yr feature. |
| 3.5 | **Adversary-emulation validation loop** — Atomic Red Team YAMLs + MITRE Caldera + Velociraptor agent. `threat_hunter_agent` runs Atomic tests against Velociraptor-managed endpoints; confirms detections fired in Wazuh / Suricata / customer SIEM; auto-generates a "detection coverage" score per ATT&CK technique. | 10d | Mandiant charges $$$ via consulting; we ship it as a premium SKU. |
| 3.6 | **Sandbox integrations** (4) | 10d | 70 % dealbreaker. |
| | • CAPEv2 (open-source) — co-deployed; Argus submits samples + ingests reports | | |
| | • Joe Sandbox Cloud — paid customer BYOK | | |
| | • Hybrid-Analysis (CrowdStrike Falcon Intelligence) — paid BYOK | | |
| | • VirusTotal Premium — **strict BYOK** (free-tier ToS forbids commercial product use; customer brings own VT Enterprise key) | | |
| 3.7 | **SOAR connectors** beyond existing Shuffle | 6d | Procurement parity. |
| | • Cortex XSOAR (Palo Alto) — incoming feed + outgoing playbook trigger | | |
| | • Tines — webhook + receiver action | | |
| | • Splunk SOAR (Phantom) — REST API + container ingest | | |
| 3.8 | **Sovereign-tenant deployment guides** — | 4d | Procurement-tickbox + sales material. |
| | • KSA — STC Cloud, Mobily, Oracle Jeddah/Riyadh region | | |
| | • UAE — G42 / Core42, Khazna, e& cloud | | |
| | • Qatar — Ooredoo cloud | | |
| | • EU — OVH, Hetzner sovereign | | |
| | • Generic — Railway sovereign region template + Helm chart | | |
| 3.9 | **HIBP Enterprise** + **IntelX** + **Dehashed** as *paid commercial-licensable* breach-credential providers; per-tenant key. | 4d | Required for enterprise sales; only HIBP / IntelX / Dehashed have clean commercial licences. |
| 3.10 | **Telegram collector** with proper legal review (Telethon-based; tracks Iranian/Arabic ransomware + hacktivist channels). Persian/Arabic NLP + LLM IOC extraction in pipeline. | 8d | High ME signal (MuddyWater, Predatory Sparrow, Cyber Av3ngers). Phase 3 because legal review takes time. |
| 3.11 | **Volatility 3** + **Velociraptor** + **CIRCL hashlookup** as `case_copilot_agent` tools — turns Argus into a full IR workbench (Recorded Future has zero forensic capability). | 5d | Premium feature; demolishes RF on IR. |
| 3.12 | **Mobile app companion** (read-only) — push alerts for Critical severity, biometric auth, alert detail view. iOS + Android via React Native or Capacitor. | 10d | Executive-visibility — buyers love seeing alerts on their phone. Optional. |

### Phase 3 — Definition of Done

- Spire Solutions can resell Argus as managed service to a Saudi bank + a Qatari telco simultaneously, with full tenant isolation and a unified MSSP console.
- A customer with CrowdStrike Falcon + Splunk + Proofpoint TAP can:
  - have CrowdStrike host telemetry enrich Argus IOC pages,
  - have Argus push IoCs to Falcon for endpoint blocking,
  - have alerts auto-routed to Splunk + Phantom playbooks,
  - have phishing URLs auto-pushed to Proofpoint blocklists.
- Argus deployable in KSA STC Cloud or UAE Core42 with a documented Helm/Compose template signed off by SAMA / NESA technical compliance teams.
- Mobile app published to TestFlight + Play Internal Test.

---

## 7. Cross-cutting / continuous workstreams

These run in parallel to phases — small effort weekly, compounding value.

### 7.1 Feed-license hygiene
Every quarter, re-verify the ToS of every wired feed. Track per-feed in `feed_health`. Hard NOs (must never enter the SaaS): VirusTotal free, GreyNoise community, OpenPhish community, urlscan free, Citizen Lab CC-BY-NC, scylla.so / snusbase.

### 7.2 Threat-actor playbook curation
Maintain `actor_playbooks` rows for the regional cluster (table 2.1). Update aliases / TTPs / confidence as new public reporting lands (CIRCL, Mandiant, ESET, ClearSky, Volexity, Amnesty Tech).

### 7.3 Demo-content evolution
Keep `scripts/_augment_demo_bank_alerts.py` and friends fresh — add 1-2 new realistic alert templates per fortnight. Aim: every dashboard page tells a story.

### 7.4 Compliance content
NCA-ECC and NESA do not exist as OSCAL packages today. Argus must ship its own control catalogue (one-time content effort, ~3 person-weeks). This becomes a defensible regional moat.

### 7.5 Documentation site
Public site at `docs.argus.gaigentic.ai` — feeds list, integrations, deployment guides, OpenAPI reference, SDK docs, compliance mapping examples. Required for sales credibility.

### 7.6 Open-source posture
A subset of Argus components could ship under Apache-2.0 (e.g. the `_seed_extra` framework, the themed `<Select>` component, the Sigma/Kestrel auto-generation logic). Open-source halo helps GCC procurement that prefers vendors with "real engineering chops" over PowerPoint vendors.

---

## 8. Pricing strategy & go-to-market

### 8.1 Pricing model recommendation

**Hybrid: per-tenant SaaS base license + per-monitored-asset add-ons.**

- **Base** (SOC tier, full Argus): **$60K – $120K / year**
- **Add-ons**:
  - per protected executive (VIP profile): $5K / year
  - per monitored brand domain (BrandTerm): $3K / year
  - per monitored BIN range: $4K / year
  - per leak keyword: $2K / year
  - per integrated SIEM/EDR/email tenant: $10K / year
  - sandbox capacity package: $15K / year
- **3-year prepaid discount**: 20 % off + locks competitors out (GCC procurement loves this)
- **MSSP partner tier**: additional 30 % discount + co-branding option

**Avoid pure flat-fee** (caps upside) **or pure per-asset** (procurement hates surprise bills).

### 8.2 Sales motion

1. **Channel-first** in GCC — bring Spire / Help AG / GBM / Mannai / Sirar / SITE / CPX / Injazat / Paramount as resellers; never sell direct in-region until $5M ARR.
2. **Reference customer first** — secure a single GCC bank (likely warm via brother) as foundational reference. Discount aggressively (50 %); name-drop with permission.
3. **Demo flow** — 15-minute Arabic-tagged dark-web → APT34 alert → Compliance Evidence Pack → Sigma rule into Splunk live. End with sovereign-deployment slide.
4. **Pilot offer** — 90-day fully-loaded pilot at no cost, signed pilot agreement requires conversion to paid on Day 90 unless explicit opt-out (creates urgency).
5. **Compliance certifications to chase** — SOC 2 Type II (12 months), ISO 27001 (6–9 months), CSA STAR Level 2 (parallel to ISO).

### 8.3 Localization matters for sales too

- Arabic sales deck (12 slides max).
- Arabic product brochure (PDF + printed).
- Arabic technical white-paper on "Threat-Intel for SAMA-Regulated Banks".
- Marketing presence at GISEC (Dubai) + Black Hat MEA (Riyadh) + Q-CYBER (Doha).
- LinkedIn presence in Arabic by founder + sales lead.

---

## 9. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Free-tier ToS violation in production (VT, GreyNoise community, OpenPhish community) | Med | High (legal + customer trust) | Hard NO list (§7.1); BYOK pattern for these; quarterly ToS audit |
| Telegram / Tor scraping legality in customer jurisdictions | Med | High | Ship as customer-opt-in feature with regional legal disclaimer; use customer-side relays for Tor in heavily regulated markets |
| Single-tenant deployment hosting cost on KSA / UAE sovereign cloud is ~3× US AWS | High | Med | Pricing reflects it; offer customer-managed Kubernetes for cost-sensitive tenants |
| OpenCTI / Wazuh / Cortex / TheHive AGPL contamination if mis-integrated | Med | High | Strict architectural rule: AGPL components only via HTTP API of co-deployed instance, never bundled / linked at code level |
| Iranian APT chooses to target Argus itself (we publicly track them) | Low | Med | Aggressive operational security; bug bounty; SOC 2 + cyber insurance |
| Brother's network warm intros don't convert to paid pilots | Med | High | Diversify channel: Black Hat MEA + GISEC presence; cold outreach to GCC CISO LinkedIn community; partner with Spire on co-marketing |
| LLM cost runaway (Claude bridge, then Anthropic API, then customer-tier) | Med | Med | Per-tenant LLM call quota; aggressive prompt caching (already wired); local LLM (Ollama) fallback for low-budget tenants |
| Compliance content drift (NCA / SAMA / NESA update frameworks) | Med | High | Subscribe to regulator update notifications; quarterly content review with regional compliance advisor |
| MaxMind / abuse.ch / OTX / AbuseIPDB suddenly go paid-only | Low | Med | All have alternatives in the feed shortlist; degrade gracefully + fall-forward to next provider |

---

## 10. Acceptance criteria — overall

A buyer-ready demo install must satisfy:

1. **Locale** — UI is English-only by design (see §2.3 decision); Hijri displayed alongside Gregorian on Reports + Compliance Evidence Pack; Compliance Evidence Pack exports support a bilingual toggle (Arabic exec summary + English technical body); user-supplied Arabic content (alert summaries, leak excerpts, phishing email bodies) renders RTL via `dir="auto"`.
2. **Coverage** — Iran-APT cluster (APT33/34/35, MuddyWater, DEV-0270, Cyber Av3ngers) all appear in `Threat Actors` with descriptions, TTPs, recent sightings.
3. **Feeds** — feed_health green for: NVD, EPSS, KEV, OTX, GreyNoise, AbuseIPDB, abuse.ch, Cloudflare Radar, MaxMind GeoLite2, plus Phase 1 #1.7 set.
4. **Compliance** — clicking "Export Evidence Pack" on any case produces a signed PDF + JSON bundle covering NCA-ECC, SAMA-CSF, NESA, Qatar NCSF, ISO 27001 A.5.7, PCI-DSS 4.0.1.
5. **Executable intel** — every alert detail page exports a Sigma rule + Kestrel hunt + Navigator layer.
6. **Open standards** — `/api/v1/taxii2/discovery` returns valid TAXII 2.1; an `stix2` Python client can subscribe.
7. **SIEM** — Splunk HEC + Sentinel + Elastic + QRadar push tested end-to-end against demo customer instances.
8. **Multi-tenant** — RLS isolation passes a red-team test (analyst from tenant A cannot see tenant B's data via any API or DB query).
9. **Sovereign deploy** — Helm chart deploys clean on a KSA STC Cloud sandbox; data-residency attestation in deploy report.
10. **Demo data** — Argus Demo Bank shows realistic distribution (3 critical / 7 high / 9 medium / 6 low / 2 info; 6 new / 4 triaged / 3 investigating / 2 confirmed / 9 resolved / 3 false-positive).

---

## 11. Open questions for the buyer — RESOLVED 2026-05-01

| # | Question | Decision |
|---|---|---|
| Q1 | Vertical focus | **Industry-agnostic** with banking-first playbook depth. All 8 compliance frameworks (NCA-ECC, SAMA-CSF, ADHICS, NESA, Qatar NCSF, ISO 27001:2022, NIST CSF 2.0, PCI-DSS 4.0.1) ship in the pack; customer picks the lens. Vertical playbooks roll out: banking → gov/sovereign → oil & gas → telco/health. Demo seed includes Demo Bank + Demo Oil & Gas + Demo Gov orgs. |
| Q2 | Reference customer | None yet. First-deal pricing assumes 50–70% discount + named-or-anonymous logo rights. |
| Q3 | Israel | **No** — at least until first 3 GCC deals close. Drop INCD content from compliance pack. Audit OSS deps for Israeli origin during P1. |
| Q4 | LLM provider | **BYOK only** (Bring-Your-Own-Key). No tiers, single SKU. Customer brings either: (a) Anthropic API key, or (b) **Gemma 4 31B** local via Ollama / vLLM (Apache-2.0, 256K context, multimodal — released April 2026). Onboarding wizard handles both paths. |
| Q5 | OSS posture | **Source-available under FSL** (Functional Source License) — converts to Apache-2.0 after 2 years. Forbids competing SaaS, allows on-prem deployment + community contribution. Apache-2.0 on integrations/SDKs/playbooks. |
| Q6 | Mobile app | **Later** (P4+ after $1M ARR). Web-mobile responsive is sufficient for v1. |
| Q7 | First-deal discount | **Yes — 50–70% for first 2 named references.** |
| Q8 | Exhibitions | **Pending brother input.** Hard deadline to decide: end of June 2026 (Black Hat MEA Riyadh booth booking). GISEC 2026 already too late. |
| Q9 | Compliance advisor retainer | **No** — no budget. Mitigation: cite NCA/SAMA/NESA primary sources directly in OSCAL pack with `source_url` + `source_version`. Brother as informal pre-launch reviewer. |
| Q10 | Branding | **Rebrand to Marsad** (مرصد — "observatory / monitoring station" in Arabic). Customer-visible surfaces use Marsad; codebase keeps internal `argus` references (modules, env vars, table names, container service names, GitHub repo) — industry norm. Domain: `marsad.xyz`. Trademark sweep (USPTO + WIPO + KSA SAIP + UAE MoE + Qatar MoCI) needed before public launch. |

### Pricing target (locked)
- Single SKU, on-prem-first, **$100K/yr or less**
- BYOK LLM (no LLM cost passed to Argus)
- 10 deals = settled-for-life target

### Rebrand scope (lock during P1)
- **Customer-visible (rebrand to Marsad):** dashboard logo + chrome, page titles + meta + favicon, login page, PDF report headers/footers, email templates, marketing copy in app, FastAPI OpenAPI title/description, docs site (when built)
- **Internal (keep as Argus):** Python modules, classes, table/column names, env var prefix (`ARGUS_*`), Docker service names (cosmetic alias optional), GitHub repo name, cookie names, log prefixes
- Effort: ~4–6 hours, single commit during P1

---

## 12. Phase summary table

| Phase | Theme | Calendar weeks | Items | Outcome |
|---|---|---|---|---|
| 🟢 P1 | Lethal in GCC | ~2 | 1.1 – 1.9 | Walk-in demos close ME deals |
| 🟡 P2 | Demolish RF / Mandiant | ~4 | 2.1 – 2.12 | Sophisticated SOC engineer picks Argus over $500K incumbents |
| 🔴 P3 | MSSP & enterprise wins | ~5–8 | 3.1 – 3.12 | $500K+ contracts via SI partners; sovereign deployments |
| ⚙️ Cross-cutting | License hygiene · actor playbooks · demo content · compliance content · docs · OSS posture | continuous | §7 | Compounding moat |

**Total focused engineering: ~14 calendar weeks** (assumes one senior eng full-time + occasional UI/content help).

---

## 13. Appendices

### 13.1 Top-10 commercial-licensable feeds to ship (priority order)

1. **abuse.ch suite** (URLhaus, MalwareBazaar, ThreatFox, Feodo, SSLBL) — CC0, massive volume, JA3/JA4 included — ✅ already wired
2. **AbuseIPDB** — clean commercial ToS — ✅ already wired
3. **AlienVault OTX** — pulses give APT context cheaply — ✅ already wired (verify LevelBlue ToS)
4. **CIRCL MISP + TAXII** — best free APT/Iran coverage — P2 #2.11
5. **CertStream + crt.sh** — backbone of brand-protect / typosquat — P1 #1.7
6. **PhishTank + CERT.PL phishing** — free, commercial-OK phishing baseline — P1 #1.7
7. **HIBP Enterprise** — only credible commercial-licensable breach API — P3 #3.9
8. **Shodan + Censys (paid)** — table-stakes for asset/exposure features — Phase 4 / customer-tier
9. **MITRE ATT&CK STIX + GHSA + ExploitDB** — vuln/exploit/TTP enrichment — ✅ partially wired; finishing in P1 #1.7
10. **ransomware.live (paid commercial tier) + DarkFeed RSS** — leak-site coverage drives executive dashboards — P3 / customer-tier

### 13.2 Top-5 OSS analysis platforms to integrate (priority order)

1. **OpenCTI** (Apache-2.0) — knowledge graph + STIX-native — P2 #2.1
2. **CISA Decider** (Apache-2.0) — auto-MITRE mapping — P2 #2.2
3. **pySigma + sigma-cli** (Apache-2.0) — Sigma rule generation + 25-dialect conversion — P2 #2.3
4. **Kestrel + STIX-Shifter** (Apache-2.0) — hunt DSL + 35-source query translation — P2 #2.4 + 2.5
5. **MISP via PyMISP** (BSD-2 client) — sharing communities, taxonomies, galaxies — P2 #2.11

### 13.3 OSS tools considered but **ignored** (with reason)

- **Maltego CE** (proprietary freemium) — link analysis; we'd export STIX/CSV for user's own Maltego.
- **Cortex / TheHive** (AGPL-3.0 server) — replicate the analyzer/responder *spec*, never bundle the AGPL code.
- **Loki / Thor full** (GPL-3.0 / non-commercial) — replicate the *rule corpus*, ship our own scanner.
- **Wazuh full server** (AGPL-3.0) — call HTTP API only; never embed.
- **scylla.so / snusbase** — legal grey zone for SaaS use.

### 13.4 Hard-NO third-party services for Argus SaaS

(Free-tier-personal-use-only. Use only via customer BYOK pattern when required.)

- VirusTotal free tier
- GreyNoise community
- OpenPhish community
- urlscan.io free
- Citizen Lab CC-BY-NC indicators
- scylla.so / snusbase

---

*End of MEGA_PHASE.md — every dealbreaker gap, every "demolish RF/Mandiant" promise, every shortlist feed, every regional-compliance framework, every OSS tool, every channel partner, and every risk now has a phase or a §7 cross-cutting home.*
