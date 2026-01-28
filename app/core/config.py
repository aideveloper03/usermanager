"""
Configuration management using Pydantic Settings.

This module provides centralized configuration for the N8N Orchestration Gateway,
with environment variable loading, validation, and type safety.
"""

from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_comma_separated(value: str | None) -> list[str]:
    """
    Parse a comma-separated string into a list.
    
    Args:
        value: Comma-separated string or None
        
    Returns:
        List of trimmed, non-empty strings
    """
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All sensitive values are loaded from environment variables and validated
    at startup to ensure the application is properly configured.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # =========================================================================
    # Application Settings
    # =========================================================================
    app_name: str = Field(
        default="N8N Orchestration Gateway",
        description="Application name displayed in docs and logs"
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version"
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode (DO NOT enable in production)"
    )
    environment: str = Field(
        default="production",
        description="Environment name (development, staging, production)"
    )
    
    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    workers: int = Field(default=4, ge=1, description="Number of worker processes")
    
    # =========================================================================
    # Supabase Configuration
    # =========================================================================
    supabase_url: str = Field(
        ...,
        description="Supabase project URL"
    )
    supabase_anon_key: str = Field(
        ...,
        description="Supabase anonymous/public key"
    )
    supabase_service_role_key: str = Field(
        ...,
        description="Supabase service role key for admin operations"
    )
    database_url: str | None = Field(
        default=None,
        description="Direct PostgreSQL connection URL (optional)"
    )
    
    # =========================================================================
    # Clerk Authentication
    # =========================================================================
    clerk_secret_key: str = Field(
        ...,
        description="Clerk secret key for backend API calls"
    )
    clerk_publishable_key: str = Field(
        ...,
        description="Clerk publishable key"
    )
    clerk_jwt_issuer: str = Field(
        ...,
        description="Clerk JWT issuer URL"
    )
    clerk_jwks_url: str = Field(
        ...,
        description="Clerk JWKS URL for JWT verification"
    )
    
    # =========================================================================
    # N8N Configuration
    # =========================================================================
    n8n_base_url: str = Field(
        ...,
        description="Base URL of the private n8n instance"
    )
    n8n_webhook_path: str = Field(
        default="/webhook",
        description="Default webhook path prefix in n8n"
    )
    n8n_internal_auth_secret: str = Field(
        ...,
        min_length=32,
        description="High-entropy secret for authenticating requests to n8n"
    )
    n8n_api_key: str | None = Field(
        default=None,
        description="n8n API key for REST API access (enables dynamic credential injection)"
    )
    n8n_request_timeout: int = Field(
        default=300,
        ge=10,
        le=600,
        description="Request timeout for n8n calls in seconds"
    )
    n8n_use_dynamic_credentials: bool = Field(
        default=False,
        description="Enable dynamic credential injection via n8n REST API"
    )
    
    # =========================================================================
    # Redis Configuration
    # =========================================================================
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    redis_password: str | None = Field(
        default=None,
        description="Redis password (if required)"
    )
    redis_ssl: bool = Field(
        default=False,
        description="Enable SSL for Redis connection"
    )
    
    # =========================================================================
    # Rate Limiting
    # =========================================================================
    rate_limit_requests: int = Field(
        default=100,
        ge=1,
        description="Maximum requests per rate limit period"
    )
    rate_limit_period: int = Field(
        default=60,
        ge=1,
        description="Rate limit period in seconds"
    )
    
    # =========================================================================
    # Security Settings
    # =========================================================================
    hmac_timestamp_tolerance: int = Field(
        default=300,
        ge=60,
        le=600,
        description="HMAC timestamp tolerance in seconds"
    )
    # Store as string to avoid pydantic-settings JSON parsing issues
    # Use cors_origins_list property to get as list
    cors_origins: str = Field(
        default="",
        description="Allowed CORS origins (comma-separated)"
    )
    trusted_proxies: str = Field(
        default="",
        description="Trusted proxy IP addresses (comma-separated)"
    )
    
    # =========================================================================
    # Developer/Testing Settings
    # =========================================================================
    dev_skip_auth: bool = Field(
        default=False,
        description="Skip authentication in development (NEVER enable in production)"
    )
    dev_default_user_id: str = Field(
        default="dev_user_001",
        description="Default user ID when DEV_SKIP_AUTH is enabled"
    )
    dev_default_org_id: str = Field(
        default="dev_org_001",
        description="Default organization ID when DEV_SKIP_AUTH is enabled"
    )
    
    # =========================================================================
    # Logging
    # =========================================================================
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
    log_format: str = Field(
        default="json",
        description="Log format (json or text)"
    )
    
    # =========================================================================
    # Feature Flags
    # =========================================================================
    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable rate limiting"
    )
    enable_hmac_validation: bool = Field(
        default=True,
        description="Enable HMAC signature validation"
    )
    enable_fingerprinting: bool = Field(
        default=True,
        description="Enable request fingerprinting"
    )
    enable_request_logging: bool = Field(
        default=True,
        description="Enable detailed request logging"
    )
    
    # =========================================================================
    # Validators
    # =========================================================================
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment name."""
        valid_envs = {"development", "staging", "production"}
        v_lower = v.lower()
        if v_lower not in valid_envs:
            raise ValueError(f"Invalid environment: {v}. Must be one of {valid_envs}")
        return v_lower
    
    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Ensure security settings are appropriate for production."""
        if self.environment == "production":
            if self.debug:
                raise ValueError("Debug mode must be disabled in production")
            if self.dev_skip_auth:
                raise ValueError("DEV_SKIP_AUTH must be disabled in production")
            if len(self.n8n_internal_auth_secret) < 64:
                raise ValueError(
                    "N8N internal auth secret should be at least 64 characters in production"
                )
        return self
    
    # =========================================================================
    # Computed Properties
    # =========================================================================
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Get CORS origins as a list."""
        return parse_comma_separated(self.cors_origins)
    
    @property
    def trusted_proxies_list(self) -> list[str]:
        """Get trusted proxies as a list."""
        return parse_comma_separated(self.trusted_proxies)
    
    @property
    def supabase_headers(self) -> dict[str, str]:
        """Get headers for Supabase API requests."""
        return {
            "apikey": self.supabase_anon_key,
            "Authorization": f"Bearer {self.supabase_service_role_key}",
        }
    
    @property
    def rate_limit_string(self) -> str:
        """Get rate limit string for SlowAPI."""
        return f"{self.rate_limit_requests}/{self.rate_limit_period}seconds"


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This function is cached to avoid re-parsing environment variables
    on every access. The cache is invalidated when the application restarts.
    """
    return Settings()


# Global settings instance for easy importing
settings = get_settings()
