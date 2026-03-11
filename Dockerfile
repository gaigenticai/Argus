FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Download DB-IP City Lite MMDB for offline geolocation (free, CC BY 4.0)
RUN mkdir -p data && \
    curl -L -o data/dbip-city-lite.mmdb.gz \
    "https://download.db-ip.com/free/dbip-city-lite-2026-03.mmdb.gz" && \
    gunzip data/dbip-city-lite.mmdb.gz && \
    ls -lh data/dbip-city-lite.mmdb

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
