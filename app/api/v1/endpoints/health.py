"""
Health Check Endpoints.

Provides health check endpoints for:
- Kubernetes/Docker health probes
- Load balancer health checks
- Service dependency monitoring
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends

from app.core.config import settings
from app.models.schemas import HealthResponse
from app.services.database import DatabaseService, get_db_service
from app.services.n8n_client import N8NClient, get_n8n_client

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "",
    response_model=HealthResponse,
    summary="Health Check",
    description="Basic health check endpoint for load balancers and orchestrators."
)
async def health_check() -> HealthResponse:
    """Basic health check - always returns healthy if service is running."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        checks={}
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    summary="Readiness Check",
    description="Readiness check that verifies all dependencies are available."
)
async def readiness_check(
    db: DatabaseService = Depends(get_db_service),
    n8n: N8NClient = Depends(get_n8n_client),
) -> HealthResponse:
    """
    Readiness check - verifies all dependencies are available.
    
    Checks:
    - Supabase database connection
    - n8n instance connectivity
    - Redis connection (if rate limiting enabled)
    """
    checks = {}
    all_healthy = True
    
    # Check Supabase connection
    try:
        # Simple query to verify connection
        db.client.table("profiles").select("id").limit(1).execute()
        checks["supabase"] = True
    except Exception as e:
        logger.warning("supabase_health_check_failed", error=str(e))
        checks["supabase"] = False
        all_healthy = False
    
    # Check n8n connectivity
    try:
        n8n_healthy = await n8n.health_check()
        checks["n8n"] = n8n_healthy
        if not n8n_healthy:
            all_healthy = False
    except Exception as e:
        logger.warning("n8n_health_check_failed", error=str(e))
        checks["n8n"] = False
        all_healthy = False
    
    # Check Redis if rate limiting is enabled
    if settings.enable_rate_limiting:
        try:
            import redis.asyncio as redis
            r = redis.from_url(settings.redis_url)
            await r.ping()
            await r.close()
            checks["redis"] = True
        except Exception as e:
            logger.warning("redis_health_check_failed", error=str(e))
            checks["redis"] = False
            # Redis failure is non-critical
    
    status = "healthy" if all_healthy else "degraded"
    
    return HealthResponse(
        status=status,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        checks=checks
    )


@router.get(
    "/live",
    response_model=HealthResponse,
    summary="Liveness Check",
    description="Liveness probe for Kubernetes - indicates if the process should be restarted."
)
async def liveness_check() -> HealthResponse:
    """
    Liveness check - indicates if the process is alive.
    
    This should only fail if the process is in an unrecoverable state.
    """
    return HealthResponse(
        status="alive",
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        checks={}
    )
