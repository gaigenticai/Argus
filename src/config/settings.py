"""Argus configuration — all settings from environment variables.

Argus is a single-tenant, self-hosted product: one customer per docker
install. The settings object exposes infrastructure addresses, secrets,
and runtime tunables. *Domain* configuration that operators tune at
runtime — fraud thresholds, rating weights, brand allowlists, crawler
targets — is stored in the database (see ``src/models/admin.py``) and
edited through the dashboard, not via env vars.
"""

from __future__ import annotations


from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator
from typing import Optional

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(_env_path)


class DatabaseSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_DB_"}

    host: str = "localhost"
    port: int = 5432
    name: str = "argus"
    user: str = "argus"
    password: Optional[str] = None

    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 280

    @model_validator(mode="after")
    def _require_password(self) -> "DatabaseSettings":
        import os as _os
        if self.password is None:
            _testing = bool(_os.environ.get("PYTEST_CURRENT_TEST")) or bool(
                _os.environ.get("ARGUS_ALLOW_EPHEMERAL_DB_PASSWORD")
            )
            if not _testing:
                raise RuntimeError(
                    "ARGUS_DB_PASSWORD must be set. "
                    "Refusing to start with no database password — "
                    "set ARGUS_DB_PASSWORD in your environment or .env file."
                )
        return self

    @property
    def _credentials(self) -> str:
        if self.password:
            return f"{self.user}:{self.password}"
        return self.user

    @property
    def url(self) -> str:
        """Return DATABASE_URL env var if set, otherwise build from components."""
        import os
        override = os.environ.get("DATABASE_URL")
        if override:
            if override.startswith("postgresql://"):
                override = override.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif override.startswith("postgres://"):
                override = override.replace("postgres://", "postgresql+asyncpg://", 1)
            if "sslmode=" in override:
                import re
                override = re.sub(r'[?&]sslmode=[^&]*', '', override)
                if '?' not in override and '&' in override:
                    override = override.replace('&', '?', 1)
            return override
        return f"postgresql+asyncpg://{self._credentials}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_url(self) -> str:
        import os
        override = os.environ.get("DATABASE_URL")
        if override:
            if "+asyncpg" in override:
                return override.replace("+asyncpg", "")
            if override.startswith("postgres://"):
                return override.replace("postgres://", "postgresql://", 1)
            return override
        return f"postgresql://{self._credentials}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_REDIS_"}

    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None

    @property
    def url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}"
        return f"redis://{self.host}:{self.port}"


class TorSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_TOR_"}

    socks_host: str = "localhost"
    socks_port: int = 9050
    control_port: int = 9051
    control_password: str = ""
    circuit_rotate_interval: int = 300

    @property
    def socks_proxy(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"


class LLMSettings(BaseSettings):
    """LLM provider configuration.

    Argus is sold to regulated banks. Sending raw intel + asset lists
    + VIP emails to a third-party LLM SaaS is a deal-killer in vendor
    review. The default points at a local Ollama instance the customer
    runs themselves; pointing at any external provider is an explicit
    operator choice that requires both a base URL and an API key.

    Supported providers:
        * ``ollama``     — local; HTTP at ``base_url``, no key required
        * ``openai``     — any OpenAI-compatible endpoint (Azure OpenAI,
                           on-prem vLLM, OpenAI proper); requires api_key.
                           Also covers ``vllm`` deployments serving
                           Gemma-4-31B / Llama-3 etc. via the OpenAI API.
        * ``anthropic``  — Anthropic Messages API; requires api_key
        * ``bridge``     — Redis-RPC to the local bridge worker which
                           shells out to the operator's installed
                           ``claude`` CLI. No api_key, no HTTP base_url —
                           just Redis. See ``bridge/bridge.py`` and
                           ``src/llm/bridge_client.py``.

    When ``provider`` is set but the required credentials are missing,
    LLM-dependent agents will refuse to run rather than silently fall
    back to a degraded result.
    """

    model_config = {"env_prefix": "ARGUS_LLM_"}

    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    api_key: Optional[str] = None
    # Per-call LLM timeout. Investigation/Triage prompts can be large
    # (full alert context + tool catalogue + history) and the bridge
    # transport adds host-CLI startup overhead. 120s was tight enough
    # that a single slow-tail call would fail entire investigations
    # at the agent's MAX_ITERATIONS=6 budget. 240s gives headroom for
    # the long-tail without making degraded-bridge failures take
    # forever (the agent retries once on transport error so the worst
    # case is bounded at 2× this value, then bubble up).
    request_timeout_seconds: int = 240
    max_concurrent_calls: int = 4

    @property
    def is_configured(self) -> bool:
        """True if the provider has everything it needs to dispatch a request."""
        if not self.provider:
            return False
        if self.provider == "ollama":
            return bool(self.base_url and self.model)
        if self.provider in ("openai", "anthropic"):
            return bool(self.base_url and self.model and self.api_key)
        if self.provider == "bridge":
            # Bridge talks to the local claude CLI through redis. Redis
            # is a hard dependency of the platform anyway, so the only
            # thing we need is a non-empty model id (used for audit
            # provenance — the worker overrides with the real model id
            # on each successful call).
            return bool(self.model)
        return False


class NotificationSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_NOTIFY_"}

    slack_webhook_url: Optional[str] = None
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 587
    email_smtp_user: Optional[str] = None
    email_smtp_password: Optional[str] = None
    email_from: str = "argus@localhost"
    email_to: list[str] = []
    pagerduty_routing_key: Optional[str] = None


class CrawlerSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_CRAWLER_"}

    max_concurrent: int = 5
    request_delay_min: float = 2.0
    request_delay_max: float = 8.0
    max_retries: int = 3
    timeout: int = 60
    user_agent_rotate: bool = True


class I2PSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_I2P_"}

    proxy_host: str = "127.0.0.1"
    proxy_port: int = 4444
    timeout: int = 120
    enabled: bool = False

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"


class LokinetSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_LOKINET_"}

    timeout: int = 90
    enabled: bool = False


class FeedSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_FEED_"}

    enabled: bool = True
    maxmind_license_key: Optional[str] = None
    maxmind_db_path: str = "data/dbip-city-lite.mmdb"
    ipapi_batch_size: int = 100
    ipapi_rate_limit: int = 15
    dedup_window_hours: int = 24
    cleanup_expired_hours: int = 6
    otx_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    abuse_ch_api_key: Optional[str] = None
    cf_radar_api_key: Optional[str] = None


class IntegrationSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_INT_"}

    opencti_url: Optional[str] = None
    opencti_api_key: Optional[str] = None
    wazuh_url: Optional[str] = None
    wazuh_user: Optional[str] = None
    wazuh_password: Optional[str] = None
    nuclei_binary: str = "nuclei"
    nuclei_templates: str = "/app/data/nuclei-templates"
    nuclei_templates_version: str = ""  # locked at build time; informational
    yara_rules_dir: str = "/app/data/yara_rules"
    sigma_rules_dir: str = "/app/data/sigma_rules"
    spiderfoot_url: Optional[str] = None
    spiderfoot_api_key: Optional[str] = None
    shuffle_url: Optional[str] = None
    shuffle_api_key: Optional[str] = None
    gophish_url: Optional[str] = None
    gophish_api_key: Optional[str] = None
    subfinder_binary: str = "subfinder"
    httpx_binary: str = "httpx"
    naabu_binary: str = "naabu"
    nmap_binary: str = "nmap"
    testssl_binary: str = "testssl.sh"


class EvidenceSettings(BaseSettings):
    """MinIO / S3-compatible evidence vault configuration."""

    model_config = {"env_prefix": "ARGUS_EVIDENCE_"}

    endpoint_url: str = "http://localhost:9000"
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    bucket: str = "argus-evidence"
    use_path_style: bool = True
    signed_url_ttl_seconds: int = 300
    max_blob_bytes: int = 50 * 1024 * 1024  # 50 MB hard cap


class TakedownSettings(BaseSettings):
    """Takedown partner credentials.

    Each partner is opt-in. Missing credentials cause the corresponding
    adapter to refuse submission — never to fake success.
    """

    model_config = {"env_prefix": "ARGUS_TAKEDOWN_"}

    netcraft_base_url: str = "https://takedown.netcraft.com/api/v1"
    netcraft_api_key: Optional[str] = None
    # Operator-facing portal URL — used to construct ``partner_url``
    # on submitted tickets when the API response doesn't carry one.
    # The dashboard's "Open at partner" link points here.
    netcraft_portal_base_url: str = "https://takedown.netcraft.com"

    phishlabs_smtp_recipient: Optional[str] = None
    phishlabs_account_reference: Optional[str] = None

    groupib_smtp_recipient: Optional[str] = None
    groupib_account_reference: Optional[str] = None

    internal_legal_smtp_recipients: list[str] = []
    internal_legal_jira_url: Optional[str] = None
    internal_legal_jira_user: Optional[str] = None
    internal_legal_jira_token: Optional[str] = None
    internal_legal_jira_project: Optional[str] = None

    # ─── Free / self-service partners ─────────────────────────────────
    # abuse.ch URLhaus — free malware URL distribution. Sign up at
    # https://urlhaus.abuse.ch to get an Auth-Key. The adapter falls
    # back to anonymous submission when no key is set, but identified
    # submissions get attribution + history in the URLhaus dashboard.
    urlhaus_base_url: str = "https://urlhaus.abuse.ch/api"
    urlhaus_auth_key: Optional[str] = None
    urlhaus_anonymous: bool = True  # accept submissions without an auth key

    # abuse.ch ThreatFox — free IOC sharing. Same auth pattern as
    # URLhaus. Distributes domains/IPs/URLs/hashes to ~500 downstream
    # security feeds (CERTs, ISPs, AV vendors).
    threatfox_base_url: str = "https://threatfox-api.abuse.ch/api/v1"
    threatfox_auth_key: Optional[str] = None

    # Direct-registrar abuse mailer. Uses the operator's existing
    # SMTP config (ARGUS_NOTIFY_EMAIL_*) — no partner-specific creds
    # needed. The adapter does a WHOIS lookup on the target domain,
    # extracts the registrar's abuse contact, and sends a templated
    # report. Cap how many WHOIS queries we'll do per submit (some
    # registrars rate-limit aggressively).
    direct_registrar_whois_timeout_seconds: float = 8.0
    # When the WHOIS abuse contact extraction fails (rare TLDs, broken
    # WHOIS server), fall back to this catch-all if set. Typical value:
    # the operator's IR team mailbox.
    direct_registrar_fallback_recipient: Optional[str] = None


class Settings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_"}

    app_name: str = "Argus"
    debug: bool = False
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = []
    secret_key: str = ""
    jwt_secret: str = ""

    # Single-tenant identity. Empty string = first-provisioned organisation.
    # When set (e.g. to "argus-demo-bank"), the org with the matching
    # slugified name wins; mismatch with multiple rows raises at first use.
    system_organization_slug: str = ""

    # JWT signing.
    #
    # ``HS256`` (the default) uses ``ARGUS_JWT_SECRET`` directly.
    # ``RS256`` / ``ES256`` use an asymmetric private key from
    # ``ARGUS_JWT_PRIVATE_KEY_PATH`` and publish the matching public
    # key via the ``/.well-known/jwks.json`` endpoint so downstream
    # services can verify tokens without sharing the secret.
    #
    # Bank prospects who require a JWKS endpoint set:
    #     ARGUS_JWT_ALGORITHM=RS256
    #     ARGUS_JWT_PRIVATE_KEY_PATH=/run/secrets/jwt-private.pem
    #     ARGUS_JWT_KEY_ID=<rotation marker, e.g. "2026-04">
    jwt_algorithm: str = "HS256"
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""
    jwt_key_id: str = "hs256-default"

    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    tor: TorSettings = Field(default_factory=TorSettings)
    i2p: I2PSettings = Field(default_factory=I2PSettings)
    lokinet: LokinetSettings = Field(default_factory=LokinetSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    crawler: CrawlerSettings = Field(default_factory=CrawlerSettings)
    notify: NotificationSettings = Field(default_factory=NotificationSettings)
    feeds: FeedSettings = Field(default_factory=FeedSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)
    takedown: TakedownSettings = Field(default_factory=TakedownSettings)


settings = Settings()
