from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="b2b-orchestration-gateway")
    environment: str = Field(default="production")

    supabase_url: AnyUrl
    supabase_anon_key: str
    supabase_service_role_key: str

    clerk_jwks_url: AnyUrl
    clerk_issuer: str | None = None
    clerk_audience: str | None = None

    n8n_webhook_url: AnyUrl
    n8n_internal_secret: str

    redis_url: str = Field(default="redis://localhost:6379/0")
    rate_limit: str = Field(default="30/minute")

    hmac_max_age_seconds: int = Field(default=300, ge=60)
    request_timeout_seconds: int = Field(default=60, ge=5)

    allowed_origins: List[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()
