# Air-gap operations

Argus is single-tenant on-prem, deployed via docker compose into the
customer's environment. This doc is the operator's checklist for
locking outbound traffic and answering "can this run with no
internet?" — the short version is **yes, almost entirely**, with the
specific exceptions enumerated below and a documented offline
alternative for every one.

## Categories

The table at the bottom of this file classifies every outbound
network call Argus can make into one of four categories:

* **always-local** — never reaches the public internet (DB, MinIO,
  Ollama, internal SIEM, etc.). No action needed.
* **public-feed** — pulls data from a known list of public feed
  URLs. Air-gap mitigation: mirror the feed inside the customer's
  network and point Argus at the mirror via env-var override.
* **target-driven** — reaches out to whatever URL / IP the operator
  registered as a brand-protection or EASM target. By definition
  this traffic is required for the feature to work; the customer
  must allow outbound for those specific targets.
* **third-party-saas** — calls a SaaS the customer has explicitly
  configured (Slack/Teams/PagerDuty webhook, Netcraft takedown
  partner, Z.AI / OpenAI LLM endpoint). Not on by default; only
  active if the operator put credentials in `.env`.

## Locking it down

The recommended deployment posture for a fully air-gapped install:

1. **Block all outbound traffic at the firewall by default.**
2. **Allow only the customer-internal targets** the operator wants
   to scan (their own domains, IP ranges, internal SaaS).
3. **Configure local mirrors** for every public-feed entry below.
   The mirror URL goes into `.env`; Argus already supports per-feed
   URL overrides for every public source.
4. **Disable the SaaS-touching features** by leaving their env vars
   blank. Argus's `is_configured` checks fail-closed — adapters
   refuse to dispatch without credentials, surfacing as
   `unconfigured` in the FeedHealth dashboard.
5. **LLM**: run [Ollama](https://ollama.com/) inside the customer's
   network and set `ARGUS_LLM_BASE_URL=http://ollama.internal:11434`.
   The LLM agents already default to Ollama (see audit S11 close-out).

## What still works fully air-gapped

Once the above posture is applied:

* All authentication, authorization, RBAC, MFA
* All UI, dashboards, settings, retention, audit log
* Asset registry, onboarding wizard, vendor / TPRM workflows
* Case management, takedown ticket workflow (with a manual or
  internal-legal adapter — Netcraft / PhishLabs / Group-IB are
  off)
* DLP regex policies, card / BIN leakage, BIN database
* Brand subsidiary allowlist, all detector tuning via AppSetting
* SOC2 evidence export, retention engine, MinIO blob lifecycle
* Notifications via internal SMTP, internal webhook, internal SIEM
* The full agent / triage / correlation pipeline against a local
  Ollama instance

## What needs offline mirrors to keep working

Each row below is a public feed Argus pulls. Set the corresponding
env-var to a mirror URL inside the customer's network and the feature
works air-gapped:

| Feed | Default URL | Override env var | Update cadence |
|---|---|---|---|
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | `ARGUS_WORKER_KEV_URL` | daily |
| NIST NVD | `nvd.nist.gov/feeds/json/cve/2.0/` | `ARGUS_WORKER_NVD_URL` | daily |
| FIRST EPSS | `epss.cyentia.com/epss_scores-current.csv.gz` | `ARGUS_WORKER_EPSS_URL` | daily |
| PhishTank | `data.phishtank.com/data/online-valid.json` | `ARGUS_FEED_PHISHTANK_URL` | hourly |
| OpenPhish | `openphish.com/feed.txt` | `ARGUS_FEED_OPENPHISH_URL` | hourly |
| URLhaus | `urlhaus.abuse.ch/downloads/csv_recent/` | `ARGUS_FEED_URLHAUS_URL` | hourly |
| abuse.ch SSL Blacklist | `sslbl.abuse.ch/blacklist/sslblacklist.csv` | `ARGUS_FEED_SSL_URL` | hourly |
| abuse.ch ThreatFox | `threatfox-api.abuse.ch/api/v1/` | `ARGUS_FEED_THREATFOX_URL` | hourly |
| Tor exit list | `check.torproject.org/torbulkexitlist` | `ARGUS_FEED_TOR_NODES_URL` | 30 min |
| ipsum (open-source IP blocklist) | `raw.githubusercontent.com/stamparm/ipsum/...` | `ARGUS_FEED_IPSUM_URL` | hourly |
| FireHOL Level 1 | `lists.blocklist.de/lists/all.txt` | `ARGUS_FEED_FIREHOL_URL` | hourly |
| DShield InfoCon | `isc.sans.edu/api/...` | `ARGUS_FEED_DSHIELD_URL` | 5 min |
| crt.sh CT logs | `crt.sh/?q=...` | `ARGUS_FEED_CRTSH_URL` | per-scan |
| MaxMind / DB-IP MMDB | bundled in image | `ARGUS_FEED_MAXMIND_DB_PATH` | per-build |

A typical mirror is a cron job on a customer-side VM that runs
`curl -o /var/www/feeds/...` against the upstream URL on the
documented cadence and serves the resulting files via nginx /
internal S3 / artefact registry.

The Dockerfile already bundles MMDB + nuclei-templates + YARA-rules
+ Sigma-rules at build time, so those don't need a runtime mirror.

## What does NOT work air-gapped (and the alternative)

* **EASM external scans** — subfinder, naabu, httpx, nmap, nuclei
  attack the targets the operator registered. If those targets are
  on the public internet, Argus must reach them. If they're inside
  the customer's network, no public-internet traffic is needed.
  Operators wanting both worlds run two Argus deployments: one in
  a DMZ for external surface, one inside the perimeter for internal
  surface.
* **CertStream** — the wss feed at `certstream.calidog.io` is a
  one-way pull; the customer can mirror it by running the
  open-source [certstream-server](https://github.com/CaliDog/certstream-server)
  inside their network and pointing `ARGUS_WORKER_CERTSTREAM_URL`
  at it.
* **Mobile-app monitors (Google Play, iTunes)** — these scrape the
  store APIs directly. There's no offline alternative beyond
  disabling the feature; banks that need it generally accept the
  outbound traffic to `play.google.com` and `itunes.apple.com`.
* **Social-platform monitors** (Twitter/Instagram/TikTok/LinkedIn) —
  same as above. These are off by default.
* **Takedown via Netcraft/PhishLabs/Group-IB** — these *are*
  third-party SaaS by design. Banks that don't allow that traffic
  use the `manual` or `internal_legal` adapter (multi-recipient SMTP
  + Jira issue) instead.
* **Crawlers** (Tor, I2P, Lokinet, Telegram, Matrix, ransomware,
  stealer markets) — by definition these reach the public internet.
  Banks that don't want to participate in dark-web monitoring
  remove all `crawler_targets` rows from the dashboard; the
  scheduler then records each kind as `unconfigured` in the
  FeedHealth panel.

## Verifying the lock-down

After applying the posture, the `/admin/feed-health` panel shows
exactly which feeds are running. A clean air-gap install shows:

* every public-feed entry as `ok` (talking to the mirror) or
  `disabled` (the feed has been turned off)
* every SaaS-touching feature as `unconfigured`
* the LLM panel showing `ollama @ ollama.internal:11434`

If any feed shows `network_error`, `auth_error`, or `unconfigured`
unexpectedly, it's almost always a missing mirror URL or a
firewall-allow-list miss.

## Dependency on the runtime image

The Argus image ships with:

* nuclei-templates pinned to a release tag (no runtime fetch)
* YARA-Rules + Sigma rules bundled at build time
* DB-IP City Lite GeoIP MMDB bundled at build time
* No `nuclei -update-templates` at runtime — the image builds once
  and all templates are version-pinned

Air-gap operators who want to update these datasets rebuild the
image inside their network with the same Dockerfile, pointing the
`COPY` / `curl` URLs at internal mirrors. The Dockerfile is
deterministic across rebuilds (every binary version is pinned in
build args).

## TL;DR for the regulated-bank prospect

> "Argus runs fully air-gapped against an internal Ollama
> instance, with documented mirror URLs for every public feed it
> consumes, and explicit fail-closed behaviour for every SaaS
> integration. No traffic leaves the customer's network unless the
> operator has explicitly configured an outbound destination."
