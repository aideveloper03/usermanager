"""
Security utilities for the N8N Orchestration Gateway.

This module provides:
- Clerk JWT verification using JWKS (simple approach)
- HMAC signature validation for anti-hijacking
- Input sanitization
- Request fingerprinting
- API key management
"""

import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from app.core.config import settings

logger = structlog.get_logger(__name__)


# =============================================================================
# HMAC SIGNATURE VALIDATION
# =============================================================================


class HMACValidationError(Exception):
    """Raised when HMAC signature validation fails."""
    pass


class HMACValidator:
    """
    HMAC-SHA256 signature validator for request authentication.
    
    The signature is computed as:
        HMAC-SHA256(client_secret, timestamp + request_body)
    """
    
    def __init__(self, timestamp_tolerance: int = 300):
        self.timestamp_tolerance = timestamp_tolerance
    
    def compute_signature(
        self,
        client_secret: str,
        timestamp: str,
        body: bytes
    ) -> str:
        """Compute HMAC-SHA256 signature for a request."""
        message = timestamp.encode() + body
        signature = hmac.new(
            client_secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def validate_timestamp(self, timestamp: str) -> bool:
        """Validate that the timestamp is within the allowed tolerance."""
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            age = abs(current_time - request_time)
            return age <= self.timestamp_tolerance
        except (ValueError, TypeError):
            return False
    
    def validate_signature(
        self,
        client_secret: str,
        timestamp: str,
        body: bytes,
        provided_signature: str
    ) -> bool:
        """Validate the provided HMAC signature."""
        if not self.validate_timestamp(timestamp):
            raise HMACValidationError(
                f"Request timestamp is too old (tolerance: {self.timestamp_tolerance}s)"
            )
        
        expected_signature = self.compute_signature(client_secret, timestamp, body)
        
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise HMACValidationError("Invalid signature")
        
        return True


hmac_validator = HMACValidator(timestamp_tolerance=settings.hmac_timestamp_tolerance)


# =============================================================================
# CLERK JWT VERIFICATION
# =============================================================================


class JWTVerificationError(Exception):
    """Raised when JWT verification fails."""
    pass


class ClerkJWTVerifier:
    """
    Clerk JWT verification using JWKS.
    
    Uses simple JWKS fetching and caching for JWT validation.
    """
    
    def __init__(self, jwks_url: str, issuer: str, cache_ttl: int = 3600):
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.cache_ttl = cache_ttl
        self._jwks: dict[str, Any] | None = None
        self._jwks_fetched_at: float = 0
    
    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from Clerk."""
        async with httpx.AsyncClient() as client:
            response = await client.get(self.jwks_url, timeout=10.0)
            response.raise_for_status()
            return response.json()
    
    async def get_jwks(self, force_refresh: bool = False) -> dict[str, Any]:
        """Get JWKS, using cache if available."""
        current_time = time.time()
        cache_expired = (current_time - self._jwks_fetched_at) > self.cache_ttl
        
        if self._jwks is None or cache_expired or force_refresh:
            self._jwks = await self._fetch_jwks()
            self._jwks_fetched_at = current_time
            logger.debug("jwks_refreshed", url=self.jwks_url)
        
        return self._jwks
    
    def _get_signing_key(self, jwks: dict[str, Any], kid: str) -> dict[str, Any]:
        """Get the signing key from JWKS by key ID."""
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        raise JWTVerificationError(f"Signing key not found for kid: {kid}")
    
    async def verify_token(self, token: str, audience: str | None = None) -> dict[str, Any]:
        """
        Verify a Clerk JWT token.
        
        Returns:
            Decoded JWT claims
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise JWTVerificationError("Missing key ID in JWT header")
            
            jwks = await self.get_jwks()
            signing_key = self._get_signing_key(jwks, kid)
            
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "require_exp": True,
                "require_iat": True,
            }
            
            if audience:
                options["verify_aud"] = True
            
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=audience,
                options=options
            )
            
            return claims
            
        except ExpiredSignatureError:
            raise JWTVerificationError("Token has expired")
        except JWTError as e:
            # Try refreshing JWKS in case keys rotated
            try:
                jwks = await self.get_jwks(force_refresh=True)
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")
                signing_key = self._get_signing_key(jwks, kid)
                
                claims = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    issuer=self.issuer,
                    audience=audience,
                    options=options
                )
                return claims
            except Exception:
                raise JWTVerificationError(f"JWT verification failed: {str(e)}")
    
    def get_user_id_from_claims(self, claims: dict[str, Any]) -> str:
        """Extract user ID from JWT claims (sub claim)."""
        user_id = claims.get("sub")
        if not user_id:
            raise JWTVerificationError("Missing user ID in token claims")
        return user_id
    
    def get_org_id_from_claims(self, claims: dict[str, Any]) -> str | None:
        """Extract organization ID from JWT claims (org_id claim)."""
        return claims.get("org_id")


jwt_verifier = ClerkJWTVerifier(
    jwks_url=settings.clerk_jwks_url,
    issuer=settings.clerk_jwt_issuer
)


# =============================================================================
# INPUT SANITIZATION
# =============================================================================


class Sanitizer:
    """Input sanitization utilities."""
    
    def __init__(self):
        # Import bleach here to avoid startup issues if not installed
        try:
            import bleach
            self._bleach = bleach
        except ImportError:
            self._bleach = None
            logger.warning("bleach not installed, sanitization will be limited")
    
    def sanitize_string(self, value: str) -> str:
        """Sanitize a string value by stripping HTML/XSS payloads."""
        if not isinstance(value, str):
            return value
        
        if self._bleach:
            return self._bleach.clean(value, tags=[], attributes={}, strip=True)
        
        # Basic sanitization without bleach
        dangerous_chars = ['<', '>', '"', "'", '&', '\\']
        result = value
        for char in dangerous_chars:
            if char == '<':
                result = result.replace(char, '&lt;')
            elif char == '>':
                result = result.replace(char, '&gt;')
        return result
    
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


sanitizer = Sanitizer()


# =============================================================================
# REQUEST FINGERPRINTING
# =============================================================================


class RequestFingerprinter:
    """Generate request fingerprints for security monitoring."""
    
    def __init__(self, salt: str | None = None):
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
    
    def compare_fingerprints(self, fingerprint1: str, fingerprint2: str) -> bool:
        """Compare two fingerprints securely."""
        return hmac.compare_digest(fingerprint1, fingerprint2)


fingerprinter = RequestFingerprinter()


# =============================================================================
# API KEY UTILITIES
# =============================================================================


class APIKeyManager:
    """Utilities for generating and verifying API keys."""
    
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
        """Generate a client secret for HMAC signing."""
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


api_key_manager = APIKeyManager()


# =============================================================================
# URL VALIDATION
# =============================================================================


def is_valid_url(url: str) -> bool:
    """Validate that a URL is well-formed."""
    try:
        parsed = urlparse(url)
        return all([
            parsed.scheme in ("http", "https"),
            parsed.netloc,
        ])
    except Exception:
        return False


def is_safe_redirect_url(url: str, allowed_hosts: list[str]) -> bool:
    """Check if a URL is safe to redirect to."""
    try:
        parsed = urlparse(url)
        return parsed.netloc in allowed_hosts
    except Exception:
        return False
