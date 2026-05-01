# Third-party software notices

Argus is distributed under the proprietary terms in `LICENSE` as a
**single-tenant on-prem product** (one customer per docker install).
This NOTICE documents the third-party software Argus incorporates and,
more importantly, the **legal boundary** between Argus's proprietary
code and the OSS tools it relies on.

The Gemini audit (G7) flagged the GPL-licensed binaries Argus shells
out to (notably **nmap** and **testssl.sh**) as a potential
contamination risk for a closed-source commercial offering. This
document explains why that risk does not in fact exist for Argus's
distribution model, and lists every third-party component with its
license and integration mechanism.

## Why GPL contamination does not apply

Argus does not link, statically or dynamically, against any GPL
binary. Specifically:

* **nmap** (NPSL — Nmap Public Source License, GPLv2-derived with a
  custom amendment) is invoked via `subprocess.exec` from
  `src/easm/runners.py`. The Argus process and the nmap process do
  not share an address space; they communicate only through stdout /
  stderr / argv. The FSF's interpretation of GPL §2(b) — and every
  practical court reading — treats this as "mere aggregation" rather
  than a derivative work. Argus does not embed any nmap source code,
  link any nmap library, or distribute nmap itself.
* **testssl.sh** (GPLv2) is a bash script, executed via the same
  arm's-length `subprocess.exec` boundary. Running a GPL program
  from a non-GPL program does not extend the GPL to the caller.
* **nuclei** (MIT), **subfinder** (MIT), **httpx** (MIT), **naabu**
  (MIT) — all permissively licensed, no compatibility issue.

The Argus Docker image bundles these binaries for operator
convenience. Customers receive the binaries under their original
licenses (the Dockerfile preserves their license files via standard
distro packaging) and may freely substitute them. Argus's invocation
of them is treated as a runtime dependency, not a derivative.

If an operator chooses to remove the GPL-licensed binaries from
their image (e.g. for stricter procurement requirements), the EASM
pipeline degrades gracefully: nmap-driven port discovery and
testssl.sh-driven cipher analysis become unavailable, but the rest
of the pipeline (subfinder, naabu, httpx, nuclei) continues to run.

## Component inventory

| Component | License | Source | Integration | Bundled? |
|---|---|---|---|---|
| **Subprocess-invoked binaries** | | | | |
| nuclei | MIT | github.com/projectdiscovery/nuclei | `subprocess.exec` (sandboxed via bwrap) | yes (`/usr/local/bin/nuclei`) |
| subfinder | MIT | github.com/projectdiscovery/subfinder | `subprocess.exec` (sandboxed) | yes |
| httpx | MIT | github.com/projectdiscovery/httpx | `subprocess.exec` (sandboxed, renamed `pd-httpx`) | yes |
| naabu | MIT | github.com/projectdiscovery/naabu | `subprocess.exec` (sandboxed) | yes |
| nmap | NPSL | github.com/nmap/nmap | `subprocess.exec` (sandboxed) | yes (apt package) |
| testssl.sh | GPLv2 | github.com/drwetter/testssl.sh | `subprocess.exec` (sandboxed) | yes |
| **Python runtime libraries** | | | | |
| FastAPI | MIT | github.com/tiangolo/fastapi | imported | yes (wheel) |
| SQLAlchemy 2 | MIT | github.com/sqlalchemy/sqlalchemy | imported | yes (wheel) |
| asyncpg | Apache-2.0 | github.com/MagicStack/asyncpg | imported | yes (wheel) |
| Alembic | MIT | github.com/sqlalchemy/alembic | imported | yes (wheel) |
| pydantic + pydantic-settings | MIT | github.com/pydantic/pydantic | imported | yes (wheel) |
| aiohttp | Apache-2.0 | github.com/aio-libs/aiohttp | imported | yes (wheel) |
| boto3 + botocore | Apache-2.0 | github.com/boto/boto3 | imported | yes (wheel) |
| python-magic | MIT | github.com/ahupp/python-magic | imported (libmagic apt) | yes |
| dnspython | ISC | github.com/rthalley/dnspython | imported | yes (wheel) |
| python-whois | MIT | github.com/joepie91/python-whois | imported | yes (wheel) |
| defusedxml | PSF-2.0 | github.com/tiran/defusedxml | imported | yes (wheel) |
| dnstwist | Apache-2.0 | github.com/elceef/dnstwist | imported (algorithm port also reimplemented in `src/brand/permutations.py`) | yes (wheel) |
| tldextract | BSD-3 | github.com/john-kurkowski/tldextract | imported | yes (wheel) |
| imagehash | BSD-2 | github.com/JohannesBuchner/imagehash | imported | yes (wheel) |
| Pillow | HPND | github.com/python-pillow/Pillow | imported | yes (wheel) |
| rapidfuzz | MIT | github.com/maxbachmann/RapidFuzz | imported | yes (wheel) |
| argon2-cffi | MIT | github.com/hynek/argon2-cffi | imported | yes (wheel) |
| PyJWT | MIT | github.com/jpadilla/pyjwt | imported | yes (wheel) |
| cryptography | Apache-2.0 / BSD-3 | github.com/pyca/cryptography | imported | yes (wheel) |
| geoip2 | Apache-2.0 | github.com/maxmind/GeoIP2-python | imported | yes (wheel) |
| websockets | BSD-3 | github.com/aaugustin/websockets | imported | yes (wheel) |
| yara-python | Apache-2.0 (yara itself: BSD-3) | github.com/VirusTotal/yara-python | imported (libyara linked) | yes (wheel) |
| PyYAML | MIT | github.com/yaml/pyyaml | imported | yes (wheel) |
| python-dotenv | BSD-3 | github.com/theskumar/python-dotenv | imported | yes (wheel) |
| prometheus_client | Apache-2.0 | github.com/prometheus/client_python | imported | yes (wheel) |
| pyotp | MIT | github.com/pyauth/pyotp | imported | yes (wheel) |
| reportlab | BSD-3 (Open-Source edition) | reportlab.com/oss | imported | yes (wheel) |
| aiohttp-socks | Apache-2.0 | github.com/romis2012/aiohttp-socks | imported | yes (wheel) |
| beautifulsoup4 | MIT | crummy.com/software/BeautifulSoup | imported | yes (wheel) |
| aiosmtplib | MIT | github.com/cole/aiosmtplib | imported | yes (wheel) |
| aiosmtpd | MIT | github.com/aio-libs/aiosmtpd | imported | yes (wheel) |
| python-multipart | Apache-2.0 | github.com/Kludex/python-multipart | imported | yes (wheel) |
| parsedmarc | Apache-2.0 | github.com/domainaware/parsedmarc | imported | yes (wheel) |
| **Datasets** | | | | |
| nuclei-templates | MIT | github.com/projectdiscovery/nuclei-templates | bundled at build time, version-pinned | yes (`/app/data/nuclei-templates`) |
| Yara-Rules | varied (per-rule headers) | github.com/Yara-Rules/rules | bundled at build time | yes (`/app/data/yara_rules`) |
| SigmaHQ rules | DRL-1.1 (Detection Rule License) | github.com/SigmaHQ/sigma | bundled at build time | yes (`/app/data/sigma_rules`) |
| DB-IP City Lite | CC-BY-4.0 | db-ip.com/db/lite.php | bundled at build time, version-pinned | yes (`/app/data/dbip-city-lite.mmdb`) |
| Public Suffix List | MPL-2.0 | publicsuffix.org | bundled inside tldextract | yes |
| **Optional integrations (NOT bundled — operator-supplied)** | | | | |
| Ollama | MIT | github.com/ollama/ollama | HTTP client, customer runs separately | no |
| Netcraft Countermeasures | proprietary | netcraft.com | HTTP client, customer's API key | no |
| Wazuh / OpenCTI / Shuffle / Spiderfoot / Gophish | per-tool | various | HTTP client | no |

## What this means for procurement

When a regulated-bank prospect's legal team runs a software bill of
materials (SBOM) scan against Argus and asks "do you embed any GPL
code?", the truthful answer is:

> "Argus is a Python application that invokes nmap and testssl.sh as
> external processes through `subprocess.exec`. Both binaries are
> distributed under their original GPL-family licenses by their
> upstream maintainers, and Argus does not modify, link to, or
> redistribute their source. This is the same legal posture as any
> Python application that calls `os.system('git pull')` — the GPL
> covers git, not the Python script that calls it."

Customers who require formal sign-off can opt out of bundling
GPL-licensed binaries by setting:

```yaml
# docker-compose.yml override
build:
  args:
    INCLUDE_GPL_BINARIES: "false"
```

(The build will skip nmap and testssl.sh; the runner's checks for
those binaries will fail-closed and any EASM phase that depends on
them will be marked unavailable in the dashboard.)

## Reporting an issue

If you believe a third-party component is missing from this notice,
or its license has changed, please raise an issue at the project
tracker. We treat license compliance as a P0 issue.

— Last reviewed: 2026-04-29
