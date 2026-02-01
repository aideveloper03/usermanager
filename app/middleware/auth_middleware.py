"""
Authentication and Security Middleware with Clerk-Supabase Native Integration.

This module provides:
- JWT authentication via Clerk with token storage for Supabase RLS
- API key authentication for machine-to-machine requests
- Developer bypass mode for local testing
- Request fingerprinting and security logging

Architecture:
    The middleware validates the Clerk JWT and stores it in request.state.
    The stored JWT is then used to create authenticated Supabase clients
    that respect RLS policies based on auth.jwt()->>'sub'.

Session Flow:
    1. Extract Bearer token from Authorization header
    2. Validate JWT against Clerk's JWKS
    3. Store validated JWT + claims in request.state
    4. Downstream code uses get_authenticated_db_service() for RLS-enabled queries
"""

import time
from typing import Any, Callable
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response, HTTPException, Depends
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
# REQUEST STATE KEYS
# =============================================================================
# These keys are used to store authentication context in request.state

STATE_USER_ID = "user_id"
STATE_ORG_ID = "org_id"
STATE_TENANT_ID = "tenant_id"
STATE_JWT_CLAIMS = "jwt_claims"
STATE_CLERK_JWT = "clerk_jwt"  # Raw JWT token for Supabase client
STATE_FINGERPRINT = "fingerprint"
STATE_REQUEST_ID = "request_id"
STATE_AUTH_METHOD = "auth_method"
STATE_IP_ADDRESS = "ip_address"
STATE_USER_AGENT = "user_agent"


# =============================================================================
# DEVELOPER BYPASS MODE
# =============================================================================


class DevBypassAuth:
    """
    Developer authentication bypass for testing.
    
    SECURITY WARNING: Never enable in production!
    
    When enabled, this bypasses all authentication and uses mock
    user/org IDs from headers or defaults. A mock JWT is generated
    for Supabase client compatibility.
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
    
    @classmethod
    def get_mock_jwt(cls) -> str:
        """
        Return a mock JWT for development mode.
        
        This is NOT a valid JWT - it's a marker that tells the database
        service to use service role access in development mode.
        """
        return "dev_bypass_mock_jwt_token"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_client_ip(request: Request) -> str:
    """Extract the real client IP address from headers or socket."""
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
    """
    Check if the path is publicly accessible (no auth required).
    
    Public paths include:
    - Health check endpoints
    - API documentation (in development)
    - Internal webhook callbacks from n8n
    """
    public_paths = {
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/internal/log-error",
        "/api/v1/internal/update-status",
    }
    
    # Health endpoints
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
    
    This middleware:
    1. Validates the authentication credentials
    2. Stores the validated JWT token in request.state for Supabase RLS
    3. Extracts user and organization context from claims
    
    The stored JWT (request.state.clerk_jwt) is used by AuthenticatedDatabaseService
    to create Supabase clients that respect RLS policies.
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
        # Generate request ID for tracing
        request_id = str(uuid4())
        request.state.request_id = request_id
        
        # Skip authentication for public paths
        if is_public_path(request.url.path):
            return await call_next(request)
        
        # Check for developer bypass mode
        if DevBypassAuth.is_enabled():
            return await self._authenticate_dev_bypass(request, call_next)
        
        # Try JWT authentication first (preferred)
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
        """Authenticate using developer bypass mode (development only)."""
        mock_claims = DevBypassAuth.get_mock_claims(request)
        
        # Store authentication context
        request.state.user_id = mock_claims["sub"]
        request.state.org_id = mock_claims.get("org_id")
        request.state.jwt_claims = mock_claims
        request.state.clerk_jwt = DevBypassAuth.get_mock_jwt()  # Mock JWT marker
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
        """
        Authenticate using Clerk JWT token.
        
        The validated token is stored in request.state.clerk_jwt for
        creating authenticated Supabase clients with RLS support.
        """
        try:
            # Validate JWT against Clerk's JWKS
            claims = await self.jwt_verifier.verify_token(token)
            
            # Extract user and organization context
            user_id = self.jwt_verifier.get_user_id_from_claims(claims)
            org_id = self.jwt_verifier.get_org_id_from_claims(claims)
            
            # Store authentication context in request state
            request.state.user_id = user_id
            request.state.org_id = org_id
            request.state.jwt_claims = claims
            request.state.clerk_jwt = token  # CRITICAL: Store raw JWT for Supabase
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
        """
        Authenticate using API key.
        
        API key authentication does NOT provide a Clerk JWT, so the
        database service will use service role access (no RLS).
        This is appropriate for machine-to-machine API calls.
        """
        if not api_key.startswith(("gw_live_", "gw_test_")):
            return self._unauthorized_response(
                "Invalid API key format",
                request.state.request_id
            )
        
        key_prefix = self.api_key_manager.extract_prefix(api_key)
        
        # Store API key info (full validation happens in endpoint)
        request.state.api_key_prefix = key_prefix
        request.state.api_key_full = api_key
        request.state.auth_method = "api_key"
        request.state.clerk_jwt = None  # No JWT for API key auth
        
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
    
    Runs after authentication to add:
    - Request fingerprinting for anomaly detection
    - Request timing and logging
    - IP and User-Agent extraction
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
        
        # Extract IP and User-Agent
        request.state.ip_address = get_client_ip(request)
        request.state.user_agent = get_user_agent(request)
        
        # Generate fingerprint
        if settings.enable_fingerprinting:
            await self._process_fingerprint(request)
        
        # Request logging with timing
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
                auth_method=getattr(request.state, STATE_AUTH_METHOD, None),
            )
            
            return response
        
        return await call_next(request)
    
    async def _process_fingerprint(self, request: Request) -> None:
        """Generate and store request fingerprint."""
        ip_address = getattr(request.state, STATE_IP_ADDRESS, get_client_ip(request))
        user_agent = getattr(request.state, STATE_USER_AGENT, get_user_agent(request))
        tenant_id = getattr(request.state, STATE_TENANT_ID, None) or \
                   request.headers.get("X-Tenant-ID", "unknown")
        
        fingerprint = self.fingerprinter.generate_fingerprint(
            ip_address=ip_address,
            user_agent=user_agent,
            tenant_id=tenant_id
        )
        
        request.state.fingerprint = fingerprint


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
    """
    FastAPI dependency to get the current authenticated user.
    
    Returns user context including:
    - user_id: Clerk user ID
    - org_id: Current organization ID (if any)
    - auth_method: How the user authenticated
    - claims: Full JWT claims (if JWT auth)
    """
    user_id = getattr(request.state, STATE_USER_ID, None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return {
        "user_id": user_id,
        "org_id": getattr(request.state, STATE_ORG_ID, None),
        "auth_method": getattr(request.state, STATE_AUTH_METHOD, None),
        "claims": getattr(request.state, STATE_JWT_CLAIMS, None),
    }


async def get_clerk_jwt(request: Request) -> str | None:
    """
    FastAPI dependency to get the raw Clerk JWT from the request.
    
    This is used to create authenticated Supabase clients with RLS support.
    Returns None for API key authentication (no JWT available).
    """
    return getattr(request.state, STATE_CLERK_JWT, None)


async def get_current_org(request: Request) -> str:
    """
    FastAPI dependency to get the current organization ID.
    
    Checks JWT claims first, then falls back to X-Tenant-ID header.
    """
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
    """
    FastAPI dependency to get full request context.
    
    Returns all authentication and security context for the request.
    """
    return {
        "request_id": getattr(request.state, STATE_REQUEST_ID, None),
        "user_id": getattr(request.state, STATE_USER_ID, None),
        "org_id": getattr(request.state, STATE_ORG_ID, None),
        "tenant_id": getattr(request.state, STATE_TENANT_ID, None),
        "auth_method": getattr(request.state, STATE_AUTH_METHOD, None),
        "clerk_jwt": getattr(request.state, STATE_CLERK_JWT, None),
        "fingerprint": getattr(request.state, STATE_FINGERPRINT, None),
        "ip_address": getattr(request.state, STATE_IP_ADDRESS, None),
        "user_agent": getattr(request.state, STATE_USER_AGENT, None),
    }


# =============================================================================
# AUTHENTICATED DATABASE SERVICE HELPER
# =============================================================================


def get_authenticated_db(request: Request):
    """
    FastAPI dependency to get an authenticated database service.
    
    Creates a database service with the Clerk JWT for RLS-enforced queries.
    Falls back to service role for API key authentication.
    
    Usage:
        @router.get("/my-data")
        async def get_my_data(db: DatabaseService = Depends(get_authenticated_db)):
            return await db.get_profile(db.user_id)
    """
    from app.services.database import (
        get_db_service,
        get_authenticated_db_service,
        DatabaseService,
    )
    
    clerk_jwt = getattr(request.state, STATE_CLERK_JWT, None)
    user_id = getattr(request.state, STATE_USER_ID, None)
    auth_method = getattr(request.state, STATE_AUTH_METHOD, None)
    
    # For JWT auth with valid token, use authenticated client with RLS
    if auth_method == "jwt" and clerk_jwt and user_id and clerk_jwt != "dev_bypass_mock_jwt_token":
        return get_authenticated_db_service(clerk_jwt, user_id)
    
    # For API key auth or dev bypass, use service role client
    return get_db_service()
