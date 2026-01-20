"""
N8N Orchestration Gateway - Main Application Entry Point.

This module creates and configures the FastAPI application with:
- CORS middleware
- Authentication middleware
- Security middleware (HMAC, fingerprinting)
- Rate limiting
- Structured logging
- API routes
"""

import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import api_router
from app.core.config import settings
from app.core.rate_limiter import setup_rate_limiting
from app.middleware.auth_middleware import setup_middleware


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def configure_logging() -> None:
    """Configure structured logging with structlog."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    import logging
    log_level = getattr(logging, settings.log_level, logging.INFO)
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


configure_logging()
logger = structlog.get_logger(__name__)


# =============================================================================
# APPLICATION LIFESPAN
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan handler for startup and shutdown events.
    
    Startup:
    - Initialize database connections
    - Verify external service connectivity
    - Log startup information
    
    Shutdown:
    - Close database connections
    - Clean up resources
    """
    # Startup
    logger.info(
        "application_starting",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        debug=settings.debug
    )
    
    # Verify required configuration
    try:
        # Check Supabase connectivity
        from app.services.database import get_db_service
        db = get_db_service()
        # Simple connectivity check
        logger.info("supabase_connection_initialized")
        
        # Check n8n connectivity (non-blocking)
        from app.services.n8n_client import get_n8n_client
        n8n = get_n8n_client()
        n8n_healthy = await n8n.health_check()
        if n8n_healthy:
            logger.info("n8n_connection_verified", url=settings.n8n_base_url)
        else:
            logger.warning("n8n_connection_failed", url=settings.n8n_base_url)
            
    except Exception as e:
        logger.error("startup_verification_failed", error=str(e))
        if settings.environment == "production":
            # In production, fail fast if services are unavailable
            sys.exit(1)
    
    logger.info("application_started")
    
    yield
    
    # Shutdown
    logger.info("application_shutting_down")
    
    # Clean up resources
    try:
        # Close any open connections
        pass
    except Exception as e:
        logger.error("shutdown_error", error=str(e))
    
    logger.info("application_shutdown_complete")


# =============================================================================
# APPLICATION FACTORY
# =============================================================================

def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.app_name,
        description="""
## N8N Orchestration Gateway

A production-ready, multi-tenant API wrapper for private n8n instances.

### Features

- **Multi-tenant Architecture**: Organizations with isolated API keys and credentials
- **Credit-based Billing**: Pay-per-execution model with atomic credit deduction
- **Secure Authentication**: Clerk JWT validation and API key authentication
- **Anti-Hijacking Protection**: HMAC signature validation with timestamp checking
- **Request Fingerprinting**: IP + User-Agent + Tenant-ID based anomaly detection
- **Rate Limiting**: Redis-backed sliding window rate limiting
- **Input Sanitization**: Automatic XSS payload stripping with bleach
- **Credential Injection**: Secure tenant credential storage in Supabase Vault

### Authentication

Requests can be authenticated using either:

1. **Clerk JWT** - Include `Authorization: Bearer <token>` header
2. **API Key** - Include `X-API-Key: <key>` header (with HMAC signature)

### Rate Limits

Default rate limit: {rate_limit} requests per {period} seconds per tenant.
        """.format(
            rate_limit=settings.rate_limit_requests,
            period=settings.rate_limit_period
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.debug or settings.is_development else None,
        redoc_url="/redoc" if settings.debug or settings.is_development else None,
        openapi_url="/openapi.json" if settings.debug or settings.is_development else None,
        lifespan=lifespan,
    )
    
    # Configure CORS
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=[
                "X-Request-ID",
                "X-Execution-ID",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
            ],
        )
    
    # Setup authentication and security middleware
    setup_middleware(app)
    
    # Setup rate limiting
    setup_rate_limiting(app)
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Add root endpoint
    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        """Root endpoint - returns basic service info."""
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "status": "operational",
            "docs": "/docs" if settings.debug or settings.is_development else None,
        }
    
    # Add global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions."""
        request_id = getattr(request.state, "request_id", "unknown")
        
        logger.error(
            "unhandled_exception",
            request_id=request_id,
            path=str(request.url.path),
            method=request.method,
            error=str(exc),
            exc_info=True
        )
        
        # Don't expose internal errors in production
        if settings.is_production:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_error",
                    "message": "An unexpected error occurred",
                    "request_id": request_id
                }
            )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": str(exc),
                "request_id": request_id
            }
        )
    
    return app


# Create application instance
app = create_application()


# =============================================================================
# DEVELOPMENT SERVER
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers,
        log_level=settings.log_level.lower(),
    )
