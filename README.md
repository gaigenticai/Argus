# Argus

**The All-Seeing Guardian** — Agentic Dark Web Monitoring & Threat Intelligence Platform

Argus is a self-hosted, enterprise-grade threat intelligence platform that autonomously monitors the dark web, public attack surfaces, and digital footprints of organizations and their executives.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Dashboard (Next.js)                │
├─────────────────────────────────────────────────────────┤
│                      API Layer (FastAPI)                │
├──────────┬──────────┬───────────┬───────────────────────┤
│  Agents  │ Enrichment│ Ingestion │      Storage          │
│  (LLM)   │ Pipeline  │  Queue    │  (PG + pgvector)      │
├──────────┴──────────┴───────────┴───────────────────────┤
│                    Crawler Engine                        │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐  │
│  │   Tor   │ │ Telegram │ │ Paste  │ │  Surface Web │  │
│  │ Forums  │ │ Channels │ │ Sites  │ │  (CVE/GitHub) │  │
│  └─────────┘ └──────────┘ └────────┘ └──────────────┘  │
├─────────────────────────────────────────────────────────┤
│              Orchestration (Docker / K8s)                │
└─────────────────────────────────────────────────────────┘
```

## Core Capabilities

- **Dark Web Monitoring** — Tor forum crawling, marketplace scanning, paste site ingestion
- **Threat Intelligence** — CVE correlation, exploit tracking, PoC detection
- **Attack Surface Discovery** — Subdomain enumeration, port scanning, misconfiguration detection
- **VIP/Executive Protection** — Credential leak detection, impersonation monitoring, doxxing alerts
- **Agentic Triage** — LLM-powered auto-classification, correlation, and incident drafting

## Deployment

Ships as a self-hosted Docker Compose / Kubernetes deployment. Customer owns their data. Zero external dependencies.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Crawlers | Python + Tor + Playwright |
| Agent Brain | Ollama (local LLM) / Customer API key |
| Queue | Redis Streams |
| Database | PostgreSQL + pgvector |
| Search | Meilisearch |
| API | FastAPI |
| Dashboard | Next.js |

## Development

```bash
# Start infrastructure
docker compose up -d

# Install Python dependencies
pip install -r requirements.txt

# Run the platform
python -m src.main
```

## License

Proprietary — All rights reserved.
