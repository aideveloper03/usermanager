"""
Rate Limiting with SlowAPI and Redis.

This module provides:
- Redis-backed sliding window rate limiting
- Per-tenant and per-IP rate limits
- Custom rate limit responses
"""

from typing import Callable, Awaitable

import structlog
from fastapi import FastAPI, Request, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings

logger = structlog.get_logger(__name__)


def get_identifier(request: Request) -> str:
    """
    Get a unique identifier for rate limiting.
    
    Priority:
    1. Organization tenant_id (for authenticated requests)
    2. API key prefix (for API key auth)
    3. Client IP address (fallback)
    """
    # Try to get tenant_id from request state (set by auth middleware)
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        return f"tenant:{tenant_id}"
    
    # Try to get from header
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        return f"tenant:{tenant_id}"
    
    # Try API key prefix
    api_key_prefix = getattr(request.state, "api_key_prefix", None)
    if api_key_prefix:
        return f"apikey:{api_key_prefix}"
    
    # Fall back to IP address
    return f"ip:{get_remote_address(request)}"


def create_limiter() -> Limiter:
    """
    Create and configure the rate limiter.
    
    Returns:
        Configured Limiter instance
    """
    # Use Redis if available, otherwise fall back to in-memory
    storage_uri = settings.redis_url if settings.enable_rate_limiting else None
    
    limiter = Limiter(
        key_func=get_identifier,
        default_limits=[settings.rate_limit_string],
        storage_uri=storage_uri,
        strategy="moving-window",  # Sliding window for smoother rate limiting
        headers_enabled=True,  # Add X-RateLimit headers to responses
    )
    
    return limiter


# Global limiter instance
limiter = create_limiter()


async def rate_limit_exceeded_handler(
    request: Request,
    exc: RateLimitExceeded
) -> Response:
    """
    Custom handler for rate limit exceeded errors.
    
    Logs the event and returns a structured error response.
    """
    from fastapi.responses import JSONResponse
    from app.services.database import get_db_service
    
    identifier = get_identifier(request)
    request_id = getattr(request.state, "request_id", "unknown")
    
    logger.warning(
        "rate_limit_exceeded",
        identifier=identifier,
        request_id=request_id,
        path=str(request.url.path),
        limit=str(exc.detail)
    )
    
    # Log security event (async, don't await to not slow down response)
    try:
        db = get_db_service()
        await db.log_security_event(
            event_type="rate_limit_exceeded",
            severity="warning",
            ip_address=get_remote_address(request),
            user_agent=request.headers.get("User-Agent"),
            request_path=str(request.url.path),
            request_method=request.method,
            details={
                "identifier": identifier,
                "limit": str(exc.detail),
                "request_id": request_id
            }
        )
    except Exception as e:
        logger.error("failed_to_log_rate_limit_event", error=str(e))
    
    # Parse retry-after from the exception
    retry_after = 60  # Default
    if hasattr(exc, "retry_after"):
        retry_after = exc.retry_after
    
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "message": f"Rate limit exceeded. Please retry after {retry_after} seconds.",
            "retry_after": retry_after,
            "request_id": request_id
        },
        headers={
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(settings.rate_limit_requests),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(retry_after),
        }
    )


def setup_rate_limiting(app: FastAPI) -> None:
    """
    Configure rate limiting for the FastAPI application.
    
    Args:
        app: FastAPI application instance
    """
    if not settings.enable_rate_limiting:
        logger.info("rate_limiting_disabled")
        return
    
    # Add limiter to app state
    app.state.limiter = limiter
    
    # Add exception handler
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    
    logger.info(
        "rate_limiting_configured",
        limit=settings.rate_limit_string,
        storage="redis" if settings.redis_url else "memory"
    )


# =============================================================================
# RATE LIMIT DECORATORS
# =============================================================================

def rate_limit(limit: str | None = None) -> Callable:
    """
    Decorator to apply custom rate limit to an endpoint.
    
    Usage:
        @router.get("/endpoint")
        @rate_limit("10/minute")
        async def my_endpoint():
            ...
    
    Args:
        limit: Rate limit string (e.g., "10/minute", "100/hour")
               If None, uses the default limit.
    """
    return limiter.limit(limit or settings.rate_limit_string)


def rate_limit_by_ip(limit: str | None = None) -> Callable:
    """
    Decorator to apply rate limit by IP address only.
    
    Useful for endpoints that should be limited per-IP regardless
    of authentication status.
    """
    return limiter.limit(
        limit or settings.rate_limit_string,
        key_func=get_remote_address
    )


def exempt_from_rate_limit() -> Callable:
    """
    Decorator to exempt an endpoint from rate limiting.
    
    Usage:
        @router.get("/health")
        @exempt_from_rate_limit()
        async def health_check():
            ...
    """
    return limiter.exempt
