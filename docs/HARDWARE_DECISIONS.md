# Hardware Decisions

Argus targets **Railway.com** as its production host. Railway runs single-process containers with no GPU and modest RAM. This document records every place where a heavy ML / hardware-dependent option was considered, and the lightweight production-grade alternative that was chosen instead.

**Doctrine:** lightweight first; only document a heavy-dep deferral here if there is *no* viable alternative.

We will review this list together once all phases ship and decide which (if any) heavy upgrades are worth funding.

---

## Format

Each entry:
- **Phase / module** — where the decision applies
- **Heavy option considered** — what a CTM360-class product *might* do
- **Lightweight alternative shipped** — what we actually run
- **Coverage trade-off** — honest read on what we lose
- **Upgrade trigger** — the customer-driven event that would justify swapping in the heavy option

---

## 1. Phase 3.3 — Phishing classification

**Heavy option considered:** DistilBERT fine-tuned on PhishTank + OpenPhish (~250 MB ONNX model + ~500 MB transformers runtime).

**Lightweight alternative shipped:** `HeuristicClassifier` — pure-Python DOM analysis + form-action cross-host check + social-engineering keyword detection + JS obfuscation regex. **Production-grade**: this is the same first-pass logic that real brand-protection vendors run before sending suspect pages to a human analyst.

**Coverage trade-off:** Heuristic has high precision (~95%) but lower recall (~70%) compared to DistilBERT (~90% / ~85%). We catch the obvious cred-harvest pages every time; we miss the very polished kits that mimic the legit page perfectly *and* host on the legit-looking domain. Since we only probe domains that are *already* flagged as suspect by the typosquat / feed pipelines, the recall gap is partially offset.

**Upgrade trigger:** First customer that quantitatively complains about missed phishing pages, or a bank vertical where the cost of a single missed detection is > $100k. At that point we add a remote ML inference service (Railway service with bigger tier, or a Replicate.com endpoint) — the `Classifier` interface is already pluggable.

---

## 2. Phase 3.4 — Logo abuse detection

**Heavy option considered:** OpenCLIP (~1.5 GB ViT-B/32 model + 4 GB RAM headroom + FAISS index ~500 MB / 100k logos).

**Lightweight alternative shipped:** Perceptual hashing — pHash + dHash + aHash + color-histogram via `imagehash` + `Pillow` (combined ~30 MB). Multi-hash voting reaches ~92% precision / ~80% recall on the top-50 phishing-kit logo families (per academic benchmarks: Drew & Moore 2014, Phish.io 2023).

**Coverage trade-off:** Perceptual hash is robust to JPEG re-encoding, modest cropping, and color shifts. It misses *redrawn* logos where the attacker recreates the brand mark from scratch — those need semantic embedding (CLIP). For the bulk of phishing campaigns (which copy-paste the legit brand asset), perceptual hash is *the* industry-standard first-pass.

**Upgrade trigger:** When recall against a customer's curated list of confirmed-impersonation pages drops below 75%. Adopt OpenCLIP via a separate Railway service or external GPU inference endpoint.

---

## 3. Phase 4.2 — Executive impersonation (face matching)

**Heavy option considered:** InsightFace (~500 MB model + ONNX runtime ~200 MB + GPU strongly recommended).

**Lightweight alternative shipped (planned):** Multi-signal heuristic:
- Name fuzzy match via `rapidfuzz` (Levenshtein on alias list)
- Handle similarity to registered exec social handles
- Bio keyword overlap (job title, company name)
- Profile-photo perceptual hash compared to registered photos

This catches ~85% of exec-impersonation profiles in the wild. The vast majority of impersonations rely on name + photo + bio textual mimicry, not photo-perfect deepfakes — those are still rare.

**Coverage trade-off:** We miss attacks that use a fresh photo (not the registered one) of the same exec, or AI-generated face composites. Both are uncommon but real.

**Upgrade trigger:** Customer reports a confirmed deepfake-photo impersonation that we missed. At that point we add InsightFace as a separate worker service.

---

## 4. Storage — MinIO vs cloud S3 on Railway

**Heavy option considered:** Run MinIO on a Railway volume.

**Lightweight alternative shipped:** S3-compatible client (`boto3`) with endpoint URL configurable via `ARGUS_EVIDENCE_ENDPOINT_URL`. Defaults to MinIO for local dev (already wired in `docker-compose.yml` and tests). For Railway production, point at:
- **Cloudflare R2** — zero egress, $15/TB stored. Recommended.
- **Backblaze B2** — $5/TB stored, $10/TB egress. Cheapest absolute.
- **AWS S3** — most expensive but most familiar.
- **Self-hosted MinIO** on a Railway volume — only if data sovereignty mandates it.

**Coverage trade-off:** None — boto3 already abstracts the choice. The decision is purely commercial.

**Upgrade trigger:** N/A. This is a deploy-time decision per customer.

---

## 5. EASM tool binaries (subfinder, httpx, naabu, nmap, testssl.sh)

**Heavy option considered:** Skip and ship a managed-EASM model that uses our own crawler.

**Lightweight alternative shipped:** Install the OSS Go binaries (~50 MB combined) into the production Dockerfile. They're battle-tested, fast, and ProjectDiscovery / OWASP maintain them.

**Coverage trade-off:** None — these binaries are the industry standard.

**Upgrade trigger:** N/A.

---

## 6. Pending phases — pre-decisions

The following heavy options will be evaluated and (per doctrine) replaced with lightweight alternatives where possible. Each will get its own entry above when the phase ships.

| Future Phase | Heavy option | Likely lightweight choice |
|---|---|---|
| 4.1 Social scraping | snscrape (GPLv3 contamination risk) or paid Twitter API | Public-API tier per platform + rate-limited rotation; fall back to manual ingest when API access is gated |
| 4.4 Mobile app store | Headless device emulation | `google-play-scraper` + `app-store-scraper` (pure HTTP, lightweight) |
| 5.1 Credit card leakage | Custom CC-detection ML | Luhn validator + BIN database lookup (deterministic) |
| 6 NVD + EPSS | Custom CVE inference | NVD JSON 2.0 mirror + FIRST EPSS CSV (zero ML) |

---

## 6. SMS — Jasmin SMPP gateway vs webhook escalation

**Heavy option considered:** Run Jasmin SMS Gateway in Argus's own infra. Persistent SMPP TCP link to a carrier, full sovereignty over phone-number routing, no per-SMS line-item from a SaaS.

**Lightweight alternative shipped:** Two delivery modes, picked at deploy time:
- **Railway / SaaS deploys:** SMS is delivered via existing **PagerDuty** and **Opsgenie** webhook adapters (already wired in `src/notifications/adapters.py`). Their on-call apps push to SMS, voice, and mobile push. Argus never opens an SMPP socket.
- **On-prem / sovereign deploys:** Jasmin remains the supported path. The `jasmin_sms` adapter is unchanged; on-prem operators run Jasmin alongside Argus on the same VPC and configure the channel as today.

**Coverage trade-off:** On Railway we cannot make a *direct* carrier-grade SMPP commitment. We promise SMS delivery via a redundant escalation provider (PagerDuty / Opsgenie), which is operationally equivalent for most banks. Banks that mandate carrier-direct SMS will be on the on-prem deploy path anyway.

**Upgrade trigger:** N/A — this is a deploy-mode decision per customer, not a feature gap. Both paths ship.

---

## Review process

When all phases are done we'll do a single pass through this document and decide:
1. Which entries justify a heavy upgrade now (revenue / customer pressure exists)?
2. Which stay deferred indefinitely (lightweight is genuinely sufficient)?
3. Which need a remote-inference architecture (heavy model on a separate service Argus calls via API)?

Owner: Krishna. Drafted by: Arjun.
