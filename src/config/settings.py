"""Argus configuration — all settings from environment variables."""

from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from pydantic import Field
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
    password: Optional[str] = "argus"

    @property
    def _credentials(self) -> str:
        if self.password:
            return f"{self.user}:{self.password}"
        return self.user

    @property
    def url(self) -> str:
        return f"postgresql+asyncpg://{self._credentials}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_url(self) -> str:
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
    control_password: str = "argus"
    circuit_rotate_interval: int = 300  # seconds

    @property
    def socks_proxy(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"


class LLMSettings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_LLM_"}

    provider: str = "openai"  # ollama | openai | anthropic (z.ai uses openai-compatible)
    base_url: str = "https://api.z.ai/api/coding/paas/v4"
    model: str = "glm-5"
    api_key: Optional[str] = None


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
    request_delay_min: float = 2.0  # seconds
    request_delay_max: float = 8.0  # seconds
    max_retries: int = 3
    timeout: int = 60  # seconds
    user_agent_rotate: bool = True


class Settings(BaseSettings):
    model_config = {"env_prefix": "ARGUS_"}

    app_name: str = "Argus"
    debug: bool = False
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    tor: TorSettings = Field(default_factory=TorSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    crawler: CrawlerSettings = Field(default_factory=CrawlerSettings)
    notify: NotificationSettings = Field(default_factory=NotificationSettings)


settings = Settings()
