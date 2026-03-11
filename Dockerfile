FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    libffi-dev \
    unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Nuclei binary (latest stable)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -version

# Download Nuclei community templates
RUN nuclei -update-templates || true

COPY . .

# Download DB-IP City Lite MMDB for offline geolocation (free, CC BY 4.0)
RUN mkdir -p data && \
    curl -L -o data/dbip-city-lite.mmdb.gz \
    "https://download.db-ip.com/free/dbip-city-lite-2026-03.mmdb.gz" && \
    gunzip data/dbip-city-lite.mmdb.gz && \
    ls -lh data/dbip-city-lite.mmdb

# Download YARA community rules (all categories)
RUN mkdir -p data/yara_rules && \
    curl -sSL https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip -o /tmp/yara-rules.zip && \
    ls -lh /tmp/yara-rules.zip && \
    unzip -o /tmp/yara-rules.zip -d /tmp/ && \
    find /tmp/rules-master -type f \( -name '*.yar' -o -name '*.yara' \) -exec cp {} data/yara_rules/ \; && \
    rm -rf /tmp/yara-rules.zip /tmp/rules-master && \
    ls data/yara_rules/ | head -10 && \
    echo "YARA rules: $(find data/yara_rules -type f -name '*.yar' -o -name '*.yara' | wc -l) files"

# Download Sigma community rules
RUN mkdir -p data/sigma_rules && \
    curl -sSL https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip -o /tmp/sigma.zip && \
    unzip -o /tmp/sigma.zip -d data/sigma_rules/ && \
    rm /tmp/sigma.zip && \
    echo "Sigma rules: $(find data/sigma_rules -name '*.yml' | wc -l) files"

# Verify the app can import and all routes are registered
RUN python -c "\
from src.api.app import app; \
routes = [r.path for r in app.routes]; \
print('Import OK'); \
print('Routes:', len(routes)); \
assert '/api/v1/tools/' in routes, f'/tools/ route missing! Routes: {routes}'; \
print('Tools route verified')"

# Render sets $PORT dynamically; default to 8000 for local dev
ENV PORT=8000
EXPOSE 8000

CMD uvicorn src.api.app:app --host 0.0.0.0 --port $PORT
