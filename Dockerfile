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

# Verify the app can import before running
RUN python -c "from src.api.app import app; print('Import OK')"

# Render sets $PORT dynamically; default to 8000 for local dev
ENV PORT=8000
EXPOSE 8000

CMD uvicorn src.api.app:app --host 0.0.0.0 --port $PORT
