"""
Security utilities for the N8N Orchestration Gateway.

This module provides:
- Clerk JWT verification using official SDK
- Input sanitization using bleach
- Request fingerprinting
- API key hashing and verification

Uses the official clerk-backend-api SDK for JWT verification.
"""

import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import bleach
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Allowed HTML tags for bleach (empty = strip all HTML)
ALLOWED_TAGS: list[str] = []

# Allowed HTML attributes for bleach
ALLOWED_ATTRIBUTES: dict[str, list[str]] = {}


# =============================================================================
# CLERK JWT VERIFICATION (Using Official SDK)
# =============================================================================


class JWTVerificationError(Exception):
    """Raised when JWT verification fails."""
    pass


class ClerkAuthenticator:
    """
    Clerk authentication using the official clerk-backend-api SDK.
    
    This class provides JWT verification for requests authenticated
    with Clerk session tokens.
    """
    
    def __init__(self, secret_key: str):
        """
        Initialize the Clerk authenticator.
        
        Args:
            secret_key: Clerk secret key (sk_...)
        """
        self.secret_key = secret_key
        self._client = None
    
    @property
    def client(self):
        """Lazy-load the Clerk client."""
        if self._client is None:
            try:
                from clerk_backend_api import Clerk
                self._client = Clerk(bearer_auth=self.secret_key)
            except ImportError:
                logger.warning("clerk-backend-api not installed, falling back to manual verification")
                self._client = None
        return self._client
    
    async def verify_session_token(self, token: str) -> dict[str, Any]:
        """
        Verify a Clerk session token.
        
        Args:
            token: The JWT session token
            
        Returns:
            Decoded token payload/claims
            
        Raises:
            JWTVerificationError: If verification fails
        """
        if not token:
            raise JWTVerificationError("No token provided")
        
        # Try using official SDK first
        if self.client:
            try:
                return await self._verify_with_sdk(token)
            except Exception as e:
                logger.debug("SDK verification failed, trying manual", error=str(e))
        
        # Fallback to manual JWKS verification
        return await self._verify_manually(token)
    
    async def _verify_with_sdk(self, token: str) -> dict[str, Any]:
        """Verify token using official Clerk SDK."""
        import httpx
        from clerk_backend_api.security import authenticate_request
        from clerk_backend_api.security.types import AuthenticateRequestOptions
        
        # Create a mock request for the SDK
        mock_request = httpx.Request(
            method="GET",
            url="https://api.local/",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        try:
            request_state = self.client.authenticate_request(
                mock_request,
                AuthenticateRequestOptions()
            )
            
            if not request_state.is_signed_in:
                reason = getattr(request_state, 'reason', 'Unknown')
                raise JWTVerificationError(f"Authentication failed: {reason}")
            
            # Return the payload
            return request_state.payload or {}
            
        except Exception as e:
            raise JWTVerificationError(f"SDK verification failed: {str(e)}")
    
    async def _verify_manually(self, token: str) -> dict[str, Any]:
        """
        Fallback manual verification using JWKS.
        
        This method fetches the JWKS from Clerk and verifies the token manually.
        Used when the SDK is not available or fails.
        """
        import httpx
        from jose import jwt, JWTError
        from jose.exceptions import ExpiredSignatureError
        
        try:
            # Decode header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise JWTVerificationError("Missing key ID in JWT header")
            
            # Fetch JWKS
            async with httpx.AsyncClient() as client:
                response = await client.get(settings.clerk_jwks_url, timeout=10.0)
                response.raise_for_status()
                jwks = response.json()
            
            # Find the signing key
            signing_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    signing_key = key
                    break
            
            if not signing_key:
                raise JWTVerificationError(f"Signing key not found for kid: {kid}")
            
            # Verify and decode
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=settings.clerk_jwt_issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                }
            )
            
            return claims
            
        except ExpiredSignatureError:
            raise JWTVerificationError("Token has expired")
        except JWTError as e:
            raise JWTVerificationError(f"JWT verification failed: {str(e)}")
        except Exception as e:
            raise JWTVerificationError(f"Verification error: {str(e)}")
    
    def get_user_id(self, claims: dict[str, Any]) -> str:
        """Extract user ID from claims."""
        user_id = claims.get("sub")
        if not user_id:
            raise JWTVerificationError("Missing user ID (sub) in claims")
        return user_id
    
    def get_org_id(self, claims: dict[str, Any]) -> str | None:
        """Extract organization ID from claims."""
        return claims.get("org_id")
    
    def get_org_role(self, claims: dict[str, Any]) -> str | None:
        """Extract organization role from claims."""
        return claims.get("org_role")


# Global authenticator instance
clerk_auth = ClerkAuthenticator(settings.clerk_secret_key)


# =============================================================================
# INPUT SANITIZATION
# =============================================================================


class Sanitizer:
    """
    Input sanitization utilities using bleach.
    
    This class provides methods to sanitize user input to prevent
    XSS attacks and other injection vulnerabilities.
    """
    
    def __init__(
        self,
        allowed_tags: list[str] | None = None,
        allowed_attributes: dict[str, list[str]] | None = None
    ):
        """Initialize the sanitizer."""
        self.allowed_tags = allowed_tags or ALLOWED_TAGS
        self.allowed_attributes = allowed_attributes or ALLOWED_ATTRIBUTES
    
    def sanitize_string(self, value: str) -> str:
        """Sanitize a string value by stripping HTML/XSS payloads."""
        if not isinstance(value, str):
            return value
        
        return bleach.clean(
            value,
            tags=self.allowed_tags,
            attributes=self.allowed_attributes,
            strip=True
        )
    
    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively sanitize all string values in a dictionary."""
        sanitized = {}
        for key, value in data.items():
            clean_key = self.sanitize_string(key) if isinstance(key, str) else key
            
            if isinstance(value, str):
                sanitized[clean_key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[clean_key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[clean_key] = self.sanitize_list(value)
            else:
                sanitized[clean_key] = value
        
        return sanitized
    
    def sanitize_list(self, data: list[Any]) -> list[Any]:
        """Recursively sanitize all string values in a list."""
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized.append(self.sanitize_string(item))
            elif isinstance(item, dict):
                sanitized.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(self.sanitize_list(item))
            else:
                sanitized.append(item)
        return sanitized
    
    def sanitize_any(self, data: Any) -> Any:
        """Sanitize any data type."""
        if isinstance(data, str):
            return self.sanitize_string(data)
        elif isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, list):
            return self.sanitize_list(data)
        return data


# Global sanitizer instance
sanitizer = Sanitizer()


# =============================================================================
# REQUEST FINGERPRINTING
# =============================================================================


class RequestFingerprinter:
    """
    Generate request fingerprints for security monitoring.
    
    Fingerprints are hashes of (IP + User-Agent + Tenant-ID) used to detect
    suspicious activity like token theft or session hijacking.
    """
    
    def __init__(self, salt: str | None = None):
        """Initialize the fingerprinter."""
        self.salt = salt or settings.n8n_internal_auth_secret[:16]
    
    def generate_fingerprint(
        self,
        ip_address: str,
        user_agent: str,
        tenant_id: str
    ) -> str:
        """Generate a fingerprint hash."""
        normalized_ip = ip_address.lower().strip()
        normalized_ua = user_agent.lower().strip()
        normalized_tenant = tenant_id.lower().strip()
        
        fingerprint_str = f"{self.salt}:{normalized_ip}:{normalized_ua}:{normalized_tenant}"
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def compare_fingerprints(self, fp1: str, fp2: str) -> bool:
        """Compare two fingerprints securely."""
        return hmac.compare_digest(fp1, fp2)


# Global fingerprinter instance
fingerprinter = RequestFingerprinter()


# =============================================================================
# API KEY UTILITIES
# =============================================================================


class APIKeyManager:
    """
    Utilities for generating and verifying API keys.
    
    API keys are generated with a prefix for easy identification
    and hashed using SHA-256 for secure storage.
    """
    
    LIVE_PREFIX = "gw_live_"
    TEST_PREFIX = "gw_test_"
    
    def generate_api_key(self, is_test: bool = False) -> tuple[str, str, str]:
        """
        Generate a new API key.
        
        Returns:
            Tuple of (full_key, key_prefix, key_hash)
        """
        prefix = self.TEST_PREFIX if is_test else self.LIVE_PREFIX
        random_part = secrets.token_urlsafe(32)
        full_key = f"{prefix}{random_part}"
        key_hash = self.hash_key(full_key)
        key_prefix = full_key[:12]
        
        return full_key, key_prefix, key_hash
    
    def generate_client_secret(self) -> tuple[str, str]:
        """
        Generate a client secret for HMAC signing.
        
        Returns:
            Tuple of (secret, secret_hash)
        """
        secret = secrets.token_urlsafe(48)
        secret_hash = self.hash_key(secret)
        return secret, secret_hash
    
    def hash_key(self, key: str) -> str:
        """Hash an API key using SHA-256."""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def verify_key(self, provided_key: str, stored_hash: str) -> bool:
        """Verify an API key against its stored hash."""
        provided_hash = self.hash_key(provided_key)
        return hmac.compare_digest(provided_hash, stored_hash)
    
    def extract_prefix(self, key: str) -> str:
        """Extract the prefix from an API key."""
        return key[:12] if len(key) >= 12 else key


# Global API key manager instance
api_key_manager = APIKeyManager()


# =============================================================================
# TIMESTAMP VALIDATION (for replay protection)
# =============================================================================


class TimestampValidator:
    """Validates request timestamps to prevent replay attacks."""
    
    def __init__(self, tolerance_seconds: int = 300):
        """Initialize with tolerance in seconds."""
        self.tolerance = tolerance_seconds
    
    def is_valid(self, timestamp: str | int) -> bool:
        """Check if timestamp is within tolerance."""
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            age = abs(current_time - request_time)
            return age <= self.tolerance
        except (ValueError, TypeError):
            return False


# Global timestamp validator
timestamp_validator = TimestampValidator(settings.hmac_timestamp_tolerance)


# =============================================================================
# URL VALIDATION
# =============================================================================


def is_valid_url(url: str) -> bool:
    """Validate that a URL is well-formed."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ("http", "https"), parsed.netloc])
    except Exception:
        return False


def is_safe_redirect_url(url: str, allowed_hosts: list[str]) -> bool:
    """Check if a URL is safe to redirect to."""
    try:
        parsed = urlparse(url)
        return parsed.netloc in allowed_hosts
    except Exception:
        return False


# =============================================================================
# BACKWARD COMPATIBILITY
# =============================================================================

# Keep old names for backward compatibility
HMACValidationError = JWTVerificationError


class HMACValidator:
    """
    HMAC timestamp validator (simplified).
    
    Note: Full HMAC signature verification requires storing the raw secret,
    not a hash. This class only validates timestamps for replay protection.
    """
    
    def __init__(self, timestamp_tolerance: int = 300):
        self.timestamp_tolerance = timestamp_tolerance
    
    def validate_timestamp(self, timestamp: str) -> bool:
        """Validate request timestamp."""
        return timestamp_validator.is_valid(timestamp)


# Global HMAC validator for backward compatibility
hmac_validator = HMACValidator(settings.hmac_timestamp_tolerance)


# Alias for ClerkJWTVerifier (backward compatibility)
ClerkJWTVerifier = ClerkAuthenticator
jwt_verifier = clerk_auth
