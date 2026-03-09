"""FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.storage.database import init_db, close_db
from src.api.routes import organizations, alerts, crawlers, scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title="Argus",
    description="Agentic Threat Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(organizations.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(crawlers.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus"}
