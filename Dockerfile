# syntax=docker/dockerfile:1.7
#
# Two-stage build. The builder stage compiles wheels and downloads
# every external binary the EASM pipeline shells out to (subfinder,
# httpx, naabu, nmap, nuclei, testssl). The runtime stage is then
# Python + libmagic + the binaries — no compilers, no source trees.
#
# Versions are pinned. Reproducible images are non-negotiable for
# regulated buyers: the same Dockerfile must produce the same image
# byte-for-byte across rebuilds.

# ----- Build-time pins ------------------------------------------------
ARG NUCLEI_VERSION=3.3.10
ARG NUCLEI_TEMPLATES_VERSION=v10.1.5
ARG SUBFINDER_VERSION=2.6.7
ARG HTTPX_VERSION=1.6.10
# Naabu didn't ship linux_arm64 until v2.3.7 (then from v2.4.0+ continuously).
# Older pins (e.g., 2.3.3) build fine on amd64 but 404 on Apple Silicon.
ARG NAABU_VERSION=2.6.0
ARG TESTSSL_VERSION=v3.2.1
ARG DBIP_DATASET=2026-03
# Pinned to a specific release tag — reproducibility requirement for regulated buyers.
# Update SIGMA_VERSION by checking https://github.com/SigmaHQ/sigma/releases
# SigmaHQ switched from v0.x.y to date-based tags (r<YYYY-MM-DD>) in 2024.
ARG SIGMA_VERSION=r2026-04-01
# Pinned to a specific commit SHA — update by running:
#   git ls-remote https://github.com/Yara-Rules/rules HEAD | awk '{print $1}'
# Yara-Rules/rules HEAD as of 2022-04-12 (the repo has been quiet since).
# Previous pin (9f51a82c) was force-pushed off the branch and now 404s.
ARG YARA_RULES_REF=0f93570194a80d2f2032869055808b0ddcdfb360

# ----- Stage 1: builder -----------------------------------------------
FROM python:3.12-slim AS builder

ARG NUCLEI_VERSION
ARG NUCLEI_TEMPLATES_VERSION
ARG SUBFINDER_VERSION
ARG HTTPX_VERSION
ARG NAABU_VERSION
ARG TESTSSL_VERSION
ARG DBIP_DATASET
ARG SIGMA_VERSION
ARG YARA_RULES_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build-only deps. None of these end up in the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates git \
        gcc python3-dev libffi-dev libmagic1 libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --wheel-dir=/wheels -r requirements.txt

# --- Go-binary tools (ProjectDiscovery suite) -------------------------
# Each release tag pinned via build arg. We unpack into /usr/local/bin
# so the runtime stage can copy the directory in one shot.
#
# ``TARGETARCH`` is a BuildKit-supplied build arg that maps to the
# build platform (``amd64`` on x86_64, ``arm64`` on Apple Silicon /
# Linux aarch64). Hardcoding ``linux_amd64`` triggers QEMU emulation
# on arm64 hosts, which has been observed to fault with SIGTRAP
# (exit 133) inside Go binaries during the version-check step. The
# arm64-native zips ship from the same release page.
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) PD_ARCH=amd64 ;; \
      arm64) PD_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac; \
    echo "Building ProjectDiscovery suite for linux_${PD_ARCH}"; \
    mkdir -p /usr/local/bin /tmp/pd; \
    cd /tmp/pd; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${PD_ARCH}.zip" -o nuclei.zip && \
        unzip -o nuclei.zip && mv nuclei /usr/local/bin/nuclei && rm nuclei.zip; \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${PD_ARCH}.zip" -o subfinder.zip && \
        unzip -o subfinder.zip && mv subfinder /usr/local/bin/subfinder && rm subfinder.zip; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${PD_ARCH}.zip" -o httpx.zip && \
        unzip -o httpx.zip && mv httpx /usr/local/bin/pd-httpx && rm httpx.zip; \
    curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${PD_ARCH}.zip" -o naabu.zip && \
        unzip -o naabu.zip && mv naabu /usr/local/bin/naabu && rm naabu.zip; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/pd-httpx /usr/local/bin/naabu; \
    /usr/local/bin/nuclei -version; \
    /usr/local/bin/subfinder -version; \
    /usr/local/bin/pd-httpx -version; \
    /usr/local/bin/naabu -version; \
    rm -rf /tmp/pd

# --- testssl.sh (BSD/GPL-2 dual-licensed; we shell out, no embedding) -
RUN set -eux; \
    git clone --depth 1 --branch "${TESTSSL_VERSION}" https://github.com/drwetter/testssl.sh.git /opt/testssl; \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh; \
    /opt/testssl/testssl.sh --version | head -n 1

# --- Pre-fetched datasets --------------------------------------------
WORKDIR /assets

# Pin nuclei templates to a release tag so vulnerability detection is
# reproducible across rebuilds. ``-update-templates`` would pull HEAD.
RUN set -eux; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" -o /tmp/templates.tgz; \
    mkdir -p /assets/nuclei-templates; \
    tar -xzf /tmp/templates.tgz --strip-components=1 -C /assets/nuclei-templates; \
    rm /tmp/templates.tgz; \
    echo "${NUCLEI_TEMPLATES_VERSION}" > /assets/nuclei-templates/.argus-version

RUN set -eux; \
    curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${DBIP_DATASET}.mmdb.gz" -o /tmp/dbip.gz; \
    gunzip /tmp/dbip.gz; \
    mv /tmp/dbip /assets/dbip-city-lite.mmdb; \
    echo "${DBIP_DATASET}" > /assets/dbip-city-lite.version

RUN set -eux; \
    mkdir -p /assets/yara_rules; \
    curl -fsSL "https://github.com/Yara-Rules/rules/archive/${YARA_RULES_REF}.tar.gz" -o /tmp/yara.tgz; \
    mkdir -p /tmp/yara && tar -xzf /tmp/yara.tgz --strip-components=1 -C /tmp/yara; \
    find /tmp/yara -type f \( -name '*.yar' -o -name '*.yara' \) -exec cp {} /assets/yara_rules/ \; ; \
    echo "${YARA_RULES_REF}" > /assets/yara_rules/.argus-version; \
    rm -rf /tmp/yara /tmp/yara.tgz

RUN set -eux; \
    mkdir -p /assets/sigma_rules; \
    curl -fsSL "https://github.com/SigmaHQ/sigma/releases/download/${SIGMA_VERSION}/sigma_all_rules.zip" -o /tmp/sigma.zip; \
    unzip -o /tmp/sigma.zip -d /assets/sigma_rules/; \
    echo "${SIGMA_VERSION}" > /assets/sigma_rules/.argus-version; \
    rm /tmp/sigma.zip


# ----- Stage 2: runtime ----------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# Runtime OS deps:
#   libmagic1   — python-magic for evidence MIME sniffing
#   libpcap0.8  — naabu requires libpcap at runtime
#   ca-certs    — outbound HTTPS
#   curl        — HEALTHCHECK
#   nmap        — distro package; matches what every IR team has
#   bsdmainutils — testssl.sh hexdump dependency
#   bind9-dnsutils — testssl.sh / nmap helpful
#   procps      — testssl.sh kill / pgrep
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 libpcap0.8 ca-certificates curl nmap bubblewrap \
        bsdmainutils bind9-dnsutils procps openssl \
    && rm -rf /var/lib/apt/lists/*

# Install pre-built wheels from the builder stage. No compiler in
# this layer.
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# EASM binaries from the builder.
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /usr/local/bin/pd-httpx /usr/local/bin/httpx
COPY --from=builder /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=builder /opt/testssl /opt/testssl
RUN ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Datasets — nuclei templates (pinned), GeoIP, YARA, Sigma.
COPY --from=builder /assets /app/data

# Drop privileges. The image runs as `argus` (uid 10001) — every
# admission controller worth its salt rejects root.
RUN groupadd --system --gid 10001 argus \
    && useradd  --system --uid 10001 --gid argus --home /app --shell /usr/sbin/nologin argus \
    && mkdir -p /app/data /var/lib/argus \
    && chown -R argus:argus /app /var/lib/argus

# App source comes last so a code change doesn't bust the wheel layer.
COPY --chown=argus:argus . .

USER argus

EXPOSE 8000

# Self-test: imports must succeed and every external binary the
# pipeline relies on must be on PATH. Failure here surfaces during
# build, not during the first request.
RUN python -c "import shutil, sys; \
    required = ['nuclei','subfinder','httpx','naabu','nmap','testssl.sh']; \
    missing = [b for b in required if shutil.which(b) is None]; \
    sys.exit(f'missing binaries: {missing}') if missing else print('binaries OK:', required)"

# Boot self-test: import the FastAPI app to catch syntax / import errors
# during the build, not at first-request time.
#
# Settings validation (settings.py) refuses to load without real secrets,
# so we feed it stubs for this one-off import — they never make it into
# the runtime image, and the actual values come from the .env / compose
# environment when the container starts.
RUN ARGUS_DB_PASSWORD=build-stub \
    ARGUS_JWT_SECRET=build-stub-jwt-secret-not-used-at-runtime \
    MEILI_MASTER_KEY=build-stub \
    MINIO_ROOT_USER=build-stub \
    MINIO_ROOT_PASSWORD=build-stub \
    ARGUS_TOR_CONTROL_PASSWORD=build-stub \
    python -c "from src.api.app import app; \
    routes = [r.path for r in app.routes]; \
    print('Boot self-test: OK,', len(routes), 'routes')"

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD uvicorn src.api.app:app --host 0.0.0.0 --port $PORT
