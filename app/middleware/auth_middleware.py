"""
Authentication and Security Middleware.

Provides:
- JWT authentication via Clerk
- API key authentication
- Developer bypass mode for testing
- Request fingerprinting
"""

import time
from typing import Any, Callable
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.security import (
    JWTVerificationError,
    api_key_manager,
    jwt_verifier,
    fingerprinter,
)

logger = structlog.get_logger(__name__)


# =============================================================================
# DEVELOPER BYPASS MODE
# =============================================================================


class DevBypassAuth:
    """
    Developer authentication bypass for testing.
    
    SECURITY WARNING: Never enable in production!
    """
    
    DEV_USER_ID_HEADER = "X-Dev-User-ID"
    DEV_ORG_ID_HEADER = "X-Dev-Org-ID"
    
    @classmethod
    def is_enabled(cls) -> bool:
        """Check if developer bypass mode is enabled."""
        return (
            settings.dev_skip_auth 
            and settings.environment == "development"
        )
    
    @classmethod
    def get_mock_claims(cls, request: Request) -> dict[str, Any]:
        """Generate mock JWT claims for testing."""
        user_id = request.headers.get(
            cls.DEV_USER_ID_HEADER, 
            settings.dev_default_user_id
        )
        org_id = request.headers.get(
            cls.DEV_ORG_ID_HEADER,
            settings.dev_default_org_id
        )
        
        return {
            "sub": user_id,
            "org_id": org_id,
            "org_role": "admin",
            "email": f"{user_id}@dev.local",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "dev_bypass": True,
        }


# =============================================================================
# REQUEST STATE KEYS
# =============================================================================

STATE_USER_ID = "user_id"
STATE_ORG_ID = "org_id"
STATE_TENANT_ID = "tenant_id"
STATE_JWT_CLAIMS = "jwt_claims"
STATE_FINGERPRINT = "fingerprint"
STATE_REQUEST_ID = "request_id"
STATE_AUTH_METHOD = "auth_method"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_client_ip(request: Request) -> str:
    """Extract the real client IP address."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ips = [ip.strip() for ip in forwarded_for.split(",")]
        for ip in ips:
            if ip not in settings.trusted_proxies_list:
                return ip
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """Extract User-Agent header."""
    return request.headers.get("User-Agent", "unknown")


def is_public_path(path: str) -> bool:
    """Check if the path is publicly accessible."""
    public_paths = {
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/internal/log-error",
        "/api/v1/internal/update-status",
    }
    
    if path.startswith("/api/v1/health"):
        return True
    
    health_paths = {"/health", "/healthz", "/ready", "/readiness", "/liveness"}
    if path in health_paths:
        return True
    
    return path in public_paths


# =============================================================================
# AUTHENTICATION MIDDLEWARE
# =============================================================================


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for validating JWTs and API keys.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.jwt_verifier = jwt_verifier
        self.api_key_manager = api_key_manager
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any]
    ) -> Response:
        """Process the request through authentication."""
        # Generate request ID
        request_id = str(uuid4())
        request.state.request_id = request_id
        
        # Skip authentication for public paths
        if is_public_path(request.url.path):
            return await call_next(request)
        
        # Check for developer bypass mode
        if DevBypassAuth.is_enabled():
            return await self._authenticate_dev_bypass(request, call_next)
        
        # Try JWT authentication first
        auth_header = request.headers.get("Authorization")
        api_key = request.headers.get("X-API-Key")
        
        if auth_header and auth_header.startswith("Bearer "):
            return await self._authenticate_jwt(request, call_next, auth_header[7:])
        elif api_key:
            return await self._authenticate_api_key(request, call_next, api_key)
        else:
            return self._unauthorized_response(
                "Missing authentication. Provide Authorization Bearer token or X-API-Key header.",
                request_id
            )
    
    async def _authenticate_dev_bypass(
        self,
        request: Request,
        call_next: Callable[[Request], Any]
    ) -> Response:
        """Authenticate using developer bypass mode."""
        mock_claims = DevBypassAuth.get_mock_claims(request)
        
        request.state.user_id = mock_claims["sub"]
        request.state.org_id = mock_claims.get("org_id")
        request.state.jwt_claims = mock_claims
        request.state.auth_method = "dev_bypass"
        
        logger.warning(
            "dev_bypass_authenticated",
            user_id=mock_claims["sub"],
            org_id=mock_claims.get("org_id"),
            request_id=request.state.request_id,
            message="Developer bypass mode is active - DO NOT USE IN PRODUCTION"
        )
        
        return await call_next(request)
    
    async def _authenticate_jwt(
        self,
        request: Request,
        call_next: Callable[[Request], Any],
        token: str
    ) -> Response:
        """Authenticate using JWT token."""
        try:
            claims = await self.jwt_verifier.verify_token(token)
            
            user_id = self.jwt_verifier.get_user_id_from_claims(claims)
            org_id = self.jwt_verifier.get_org_id_from_claims(claims)
            
            request.state.user_id = user_id
            request.state.org_id = org_id
            request.state.jwt_claims = claims
            request.state.auth_method = "jwt"
            
            logger.debug(
                "jwt_authenticated",
                user_id=user_id,
                org_id=org_id,
                request_id=request.state.request_id
            )
            
            return await call_next(request)
            
        except JWTVerificationError as e:
            return self._unauthorized_response(
                f"JWT verification failed: {str(e)}",
                request.state.request_id
            )
        except Exception as e:
            logger.error("jwt_auth_error", error=str(e))
            return self._error_response(
                "Authentication error",
                request.state.request_id
            )
    
    async def _authenticate_api_key(
        self,
        request: Request,
        call_next: Callable[[Request], Any],
        api_key: str
    ) -> Response:
        """Authenticate using API key."""
        if not api_key.startswith(("gw_live_", "gw_test_")):
            return self._unauthorized_response(
                "Invalid API key format",
                request.state.request_id
            )
        
        key_prefix = self.api_key_manager.extract_prefix(api_key)
        request.state.api_key_prefix = key_prefix
        request.state.api_key_full = api_key
        request.state.auth_method = "api_key"
        
        logger.debug(
            "api_key_auth_pending",
            key_prefix=key_prefix,
            request_id=request.state.request_id
        )
        
        return await call_next(request)
    
    def _unauthorized_response(self, message: str, request_id: str) -> JSONResponse:
        """Return a 401 Unauthorized response."""
        return JSONResponse(
            status_code=401,
            content={
                "error": "unauthorized",
                "message": message,
                "request_id": request_id
            }
        )
    
    def _error_response(self, message: str, request_id: str) -> JSONResponse:
        """Return a 500 Internal Server Error response."""
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": message,
                "request_id": request_id
            }
        )


# =============================================================================
# SECURITY MIDDLEWARE
# =============================================================================


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for fingerprinting and request logging.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.fingerprinter = fingerprinter
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any]
    ) -> Response:
        """Process the request through security checks."""
        if is_public_path(request.url.path):
            return await call_next(request)
        
        request_id = getattr(request.state, STATE_REQUEST_ID, str(uuid4()))
        
        # Fingerprinting
        if settings.enable_fingerprinting:
            await self._process_fingerprint(request)
        
        # Request logging
        if settings.enable_request_logging:
            start_time = time.time()
            response = await call_next(request)
            duration_ms = int((time.time() - start_time) * 1000)
            
            logger.info(
                "request_completed",
                request_id=request_id,
                method=request.method,
                path=str(request.url.path),
                status_code=response.status_code,
                duration_ms=duration_ms,
                user_id=getattr(request.state, STATE_USER_ID, None),
                org_id=getattr(request.state, STATE_ORG_ID, None),
            )
            
            return response
        
        return await call_next(request)
    
    async def _process_fingerprint(self, request: Request) -> None:
        """Generate and store request fingerprint."""
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        tenant_id = getattr(request.state, STATE_TENANT_ID, None) or \
                   request.headers.get("X-Tenant-ID", "unknown")
        
        fingerprint = self.fingerprinter.generate_fingerprint(
            ip_address=ip_address,
            user_agent=user_agent,
            tenant_id=tenant_id
        )
        
        request.state.fingerprint = fingerprint
        request.state.ip_address = ip_address
        request.state.user_agent = user_agent


# =============================================================================
# MIDDLEWARE SETUP
# =============================================================================


def setup_middleware(app: FastAPI) -> None:
    """Configure all middleware for the FastAPI application."""
    # Security middleware (runs after auth)
    app.add_middleware(SecurityMiddleware)
    
    # Authentication middleware (runs first)
    app.add_middleware(AuthMiddleware)
    
    logger.info("middleware_configured", middlewares=["AuthMiddleware", "SecurityMiddleware"])


# =============================================================================
# DEPENDENCY INJECTION HELPERS
# =============================================================================


async def get_current_user(request: Request) -> dict[str, Any]:
    """FastAPI dependency to get the current authenticated user."""
    from fastapi import HTTPException
    
    user_id = getattr(request.state, STATE_USER_ID, None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return {
        "user_id": user_id,
        "org_id": getattr(request.state, STATE_ORG_ID, None),
        "auth_method": getattr(request.state, STATE_AUTH_METHOD, None),
        "claims": getattr(request.state, STATE_JWT_CLAIMS, None),
    }


async def get_current_org(request: Request) -> str:
    """FastAPI dependency to get the current organization ID."""
    from fastapi import HTTPException
    
    org_id = getattr(request.state, STATE_ORG_ID, None)
    if not org_id:
        tenant_id = getattr(request.state, STATE_TENANT_ID, None) or \
                   request.headers.get("X-Tenant-ID")
        if tenant_id:
            return tenant_id
        
        raise HTTPException(
            status_code=400,
            detail="Organization context required. Include org_id in JWT or X-Tenant-ID header."
        )
    
    return org_id


async def get_request_context(request: Request) -> dict[str, Any]:
    """FastAPI dependency to get full request context."""
    return {
        "request_id": getattr(request.state, STATE_REQUEST_ID, None),
        "user_id": getattr(request.state, STATE_USER_ID, None),
        "org_id": getattr(request.state, STATE_ORG_ID, None),
        "tenant_id": getattr(request.state, STATE_TENANT_ID, None),
        "auth_method": getattr(request.state, STATE_AUTH_METHOD, None),
        "fingerprint": getattr(request.state, "fingerprint", None),
        "ip_address": getattr(request.state, "ip_address", None),
        "user_agent": getattr(request.state, "user_agent", None),
    }
