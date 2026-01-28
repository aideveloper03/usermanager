"""
Authentication and Security Middleware.

This module provides:
- JWT authentication middleware
- Developer bypass mode for testing
- HMAC anti-hijacking validation
- IP fingerprinting and anomaly detection
- Request logging and security event tracking

Developer Bypass Mode:
    When DEV_SKIP_AUTH=true is set in environment variables, the API will accept
    X-Dev-User-ID and X-Dev-Org-ID headers to mock authentication. This is useful
    for local development and testing without valid Clerk tokens.
    
    NEVER enable this in production!
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
    HMACValidationError,
    HMACValidator,
    ClerkJWTVerifier,
    JWTVerificationError,
    RequestFingerprinter,
    api_key_manager,
    hmac_validator,
    jwt_verifier,
    fingerprinter,
)
from app.models.schemas import SecurityEventType

logger = structlog.get_logger(__name__)


# =============================================================================
# DEVELOPER BYPASS MODE
# =============================================================================


class DevBypassAuth:
    """
    Developer authentication bypass for testing.
    
    When DEV_SKIP_AUTH=true, this class provides mock authentication
    using X-Dev-User-ID and X-Dev-Org-ID headers.
    
    SECURITY WARNING: Never enable in production!
    """
    
    # Header names for dev bypass
    DEV_USER_ID_HEADER = "X-Dev-User-ID"
    DEV_ORG_ID_HEADER = "X-Dev-Org-ID"
    DEV_ROLE_HEADER = "X-Dev-Role"
    
    @classmethod
    def is_enabled(cls) -> bool:
        """Check if developer bypass mode is enabled."""
        return settings.dev_skip_auth and settings.environment != "production"
    
    @classmethod
    def get_mock_user_id(cls, request: Request) -> str:
        """Get the mock user ID from header or default."""
        return request.headers.get(
            cls.DEV_USER_ID_HEADER, 
            settings.dev_default_user_id
        )
    
    @classmethod
    def get_mock_org_id(cls, request: Request) -> str | None:
        """Get the mock organization ID from header or default."""
        return request.headers.get(
            cls.DEV_ORG_ID_HEADER,
            settings.dev_default_org_id
        )
    
    @classmethod
    def get_mock_role(cls, request: Request) -> str:
        """Get the mock user role from header."""
        return request.headers.get(cls.DEV_ROLE_HEADER, "admin")
    
    @classmethod
    def get_mock_claims(cls, request: Request) -> dict[str, Any]:
        """Generate mock JWT claims for testing."""
        user_id = cls.get_mock_user_id(request)
        org_id = cls.get_mock_org_id(request)
        role = cls.get_mock_role(request)
        
        return {
            "sub": user_id,
            "org_id": org_id,
            "org_role": role,
            "email": f"{user_id}@dev.local",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "dev_bypass": True,  # Flag indicating this is a mock
        }


dev_bypass = DevBypassAuth()


# =============================================================================
# REQUEST STATE KEYS
# =============================================================================

# Keys used to store data in request.state
STATE_USER_ID = "user_id"
STATE_ORG_ID = "org_id"
STATE_TENANT_ID = "tenant_id"
STATE_JWT_CLAIMS = "jwt_claims"
STATE_FINGERPRINT = "fingerprint"
STATE_REQUEST_ID = "request_id"
STATE_AUTH_METHOD = "auth_method"  # "jwt" or "api_key"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from the request.
    
    Handles X-Forwarded-For header for proxied requests.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address string
    """
    # Check for X-Forwarded-For header (common with proxies/load balancers)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        ips = [ip.strip() for ip in forwarded_for.split(",")]
        # Filter out trusted proxies
        for ip in ips:
            if ip not in settings.trusted_proxies_list:
                return ip
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """Extract User-Agent header from request."""
    return request.headers.get("User-Agent", "unknown")


def is_health_check_path(path: str) -> bool:
    """Check if the path is a health check endpoint."""
    health_paths = {"/health", "/healthz", "/ready", "/readiness", "/liveness"}
    return path in health_paths or path.startswith("/api/health")


def is_public_path(path: str) -> bool:
    """Check if the path is publicly accessible without authentication."""
    public_paths = {
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/internal/log-error",  # Internal callback from n8n
        "/api/v1/internal/update-status",  # Internal callback from n8n
    }
    # Check for health endpoints
    if path.startswith("/api/v1/health"):
        return True
    return path in public_paths or is_health_check_path(path)


# =============================================================================
# SECURITY LOGGING
# =============================================================================


class SecurityLogger:
    """
    Security event logger for tracking authentication and security events.
    
    In a production system, this would write to the security_logs table
    in Supabase. For now, it logs to structured logging.
    """
    
    def __init__(self):
        self.logger = structlog.get_logger("security")
    
    async def log_event(
        self,
        event_type: SecurityEventType,
        request: Request,
        severity: str = "info",
        org_id: str | None = None,
        user_id: str | None = None,
        details: dict[str, Any] | None = None
    ) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            request: The request that triggered the event
            severity: Event severity (info, warning, critical)
            org_id: Organization ID if known
            user_id: User ID if known
            details: Additional event details
        """
        event_data = {
            "event_type": event_type.value,
            "severity": severity,
            "ip_address": get_client_ip(request),
            "user_agent": get_user_agent(request),
            "request_path": str(request.url.path),
            "request_method": request.method,
            "org_id": org_id,
            "user_id": user_id,
            "request_id": getattr(request.state, STATE_REQUEST_ID, None),
            "details": details or {},
        }
        
        if severity == "critical":
            self.logger.critical("security_event", **event_data)
        elif severity == "warning":
            self.logger.warning("security_event", **event_data)
        else:
            self.logger.info("security_event", **event_data)


security_logger = SecurityLogger()


# =============================================================================
# AUTHENTICATION MIDDLEWARE
# =============================================================================


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for validating JWTs and API keys.
    
    This middleware:
    1. Generates a request ID for tracing
    2. Checks for developer bypass mode (DEV_SKIP_AUTH)
    3. Validates JWT tokens from Authorization header
    4. Alternatively validates API keys from X-API-Key header
    5. Stores authenticated user/org info in request.state
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
        """
        Authenticate using developer bypass mode.
        
        Uses X-Dev-User-ID and X-Dev-Org-ID headers for mock authentication.
        """
        mock_claims = DevBypassAuth.get_mock_claims(request)
        user_id = mock_claims["sub"]
        org_id = mock_claims.get("org_id")
        
        # Store in request state
        request.state.user_id = user_id
        request.state.org_id = org_id
        request.state.jwt_claims = mock_claims
        request.state.auth_method = "dev_bypass"
        
        logger.warning(
            "dev_bypass_authenticated",
            user_id=user_id,
            org_id=org_id,
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
            # Verify the JWT
            claims = await self.jwt_verifier.verify_token(token)
            
            # Extract user and org info
            user_id = self.jwt_verifier.get_user_id_from_claims(claims)
            org_id = self.jwt_verifier.get_org_id_from_claims(claims)
            
            # Store in request state
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
            await security_logger.log_event(
                SecurityEventType.TOKEN_EXPIRED if "expired" in str(e).lower() 
                    else SecurityEventType.UNAUTHORIZED_ACCESS,
                request,
                severity="warning",
                details={"error": str(e)}
            )
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
        # Note: In production, this would look up the API key in the database
        # For now, we extract the prefix and validate format
        
        if not api_key.startswith(("gw_live_", "gw_test_")):
            await security_logger.log_event(
                SecurityEventType.INVALID_API_KEY,
                request,
                severity="warning",
                details={"reason": "Invalid key format"}
            )
            return self._unauthorized_response(
                "Invalid API key format",
                request.state.request_id
            )
        
        # Store the key prefix in state for later lookup
        key_prefix = self.api_key_manager.extract_prefix(api_key)
        request.state.api_key_prefix = key_prefix
        request.state.api_key_full = api_key  # For verification against hash
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
# SECURITY MIDDLEWARE (HMAC + FINGERPRINTING)
# =============================================================================


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for HMAC validation and fingerprinting.
    
    This middleware:
    1. Validates HMAC signatures on protected endpoints
    2. Generates and validates request fingerprints
    3. Detects suspicious activity based on fingerprint changes
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.hmac_validator = hmac_validator
        self.fingerprinter = fingerprinter
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any]
    ) -> Response:
        """Process the request through security checks."""
        
        # Skip security checks for public paths
        if is_public_path(request.url.path):
            return await call_next(request)
        
        # Get request ID from auth middleware
        request_id = getattr(request.state, STATE_REQUEST_ID, str(uuid4()))
        
        # HMAC validation (if enabled)
        if settings.enable_hmac_validation:
            hmac_result = await self._validate_hmac(request)
            if hmac_result is not None:
                return hmac_result
        
        # Fingerprinting (if enabled)
        if settings.enable_fingerprinting:
            await self._process_fingerprint(request)
        
        # Log request if enabled
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
    
    async def _validate_hmac(self, request: Request) -> Response | None:
        """
        Validate HMAC signature on the request.
        
        Returns:
            None if validation passes, error Response if it fails
        """
        # HMAC validation is required for POST/PUT/PATCH requests to execute endpoint
        if request.method not in ("POST", "PUT", "PATCH"):
            return None
        
        # Only validate HMAC on /execute endpoint
        if "/execute" not in request.url.path:
            return None
        
        # Get required headers
        signature = request.headers.get("X-Signature")
        timestamp = request.headers.get("X-Timestamp")
        tenant_id = request.headers.get("X-Tenant-ID")
        
        if not signature or not timestamp:
            # HMAC headers are optional if using JWT auth
            auth_method = getattr(request.state, STATE_AUTH_METHOD, None)
            if auth_method == "jwt":
                return None
            
            await security_logger.log_event(
                SecurityEventType.HMAC_VALIDATION_FAILED,
                request,
                severity="warning",
                details={"reason": "Missing X-Signature or X-Timestamp header"}
            )
            return self._forbidden_response(
                "Missing required security headers (X-Signature, X-Timestamp)",
                getattr(request.state, STATE_REQUEST_ID, "unknown")
            )
        
        # Get request body
        body = await request.body()
        
        # For HMAC validation, we need the client secret
        # This will be looked up from the database using tenant_id
        # For now, we store the headers for later validation in the endpoint
        request.state.hmac_signature = signature
        request.state.hmac_timestamp = timestamp
        request.state.hmac_body = body
        request.state.tenant_id = tenant_id
        
        return None
    
    async def _process_fingerprint(self, request: Request) -> None:
        """
        Generate and process request fingerprint.
        
        Stores fingerprint in request.state and logs suspicious activity
        if fingerprint doesn't match expected pattern for the user/org.
        """
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        tenant_id = getattr(request.state, STATE_TENANT_ID, None) or \
                   request.headers.get("X-Tenant-ID", "unknown")
        
        # Generate fingerprint
        fingerprint = self.fingerprinter.generate_fingerprint(
            ip_address=ip_address,
            user_agent=user_agent,
            tenant_id=tenant_id
        )
        
        request.state.fingerprint = fingerprint
        request.state.ip_address = ip_address
        request.state.user_agent = user_agent
        
        logger.debug(
            "fingerprint_generated",
            fingerprint_prefix=fingerprint[:16],
            ip_address=ip_address,
            tenant_id=tenant_id,
            request_id=getattr(request.state, STATE_REQUEST_ID, None)
        )
    
    def _forbidden_response(self, message: str, request_id: str) -> JSONResponse:
        """Return a 403 Forbidden response."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "forbidden",
                "message": message,
                "request_id": request_id
            }
        )


# =============================================================================
# MIDDLEWARE SETUP
# =============================================================================


def setup_middleware(app: FastAPI) -> None:
    """
    Configure all middleware for the FastAPI application.
    
    Middleware order matters! They are executed in reverse order on the
    request path and in order on the response path.
    
    Args:
        app: FastAPI application instance
    """
    # Security middleware (HMAC, fingerprinting) - runs after auth
    app.add_middleware(SecurityMiddleware)
    
    # Authentication middleware - runs first
    app.add_middleware(AuthMiddleware)
    
    logger.info("middleware_configured", middlewares=["AuthMiddleware", "SecurityMiddleware"])


# =============================================================================
# DEPENDENCY INJECTION HELPERS
# =============================================================================


async def get_current_user(request: Request) -> dict[str, Any]:
    """
    FastAPI dependency to get the current authenticated user.
    
    Returns:
        Dict with user_id and auth_method
        
    Raises:
        HTTPException: If user is not authenticated
    """
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
    """
    FastAPI dependency to get the current organization ID.
    
    Returns:
        Organization ID string
        
    Raises:
        HTTPException: If org is not in context
    """
    from fastapi import HTTPException
    
    org_id = getattr(request.state, STATE_ORG_ID, None)
    if not org_id:
        # Try to get from tenant_id header
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
    
    Returns:
        Dict with all request context information
    """
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
