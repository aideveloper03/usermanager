"""
Security utilities for the N8N Orchestration Gateway.

This module provides:
- HMAC signature validation for anti-hijacking
- Clerk JWT verification
- Input sanitization using bleach
- Request fingerprinting
- API key hashing and verification
"""

import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import bleach
import httpx
import structlog
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from app.core.config import settings

logger = structlog.get_logger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Allowed HTML tags for bleach (empty = strip all HTML)
ALLOWED_TAGS: list[str] = []

# Allowed HTML attributes for bleach
ALLOWED_ATTRIBUTES: dict[str, list[str]] = {}

# JWKS cache
_jwks_cache: dict[str, Any] | None = None
_jwks_cache_time: float = 0
JWKS_CACHE_TTL = 3600  # 1 hour


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
    
    Where:
        - client_secret: Per-tenant secret stored securely
        - timestamp: Unix timestamp from X-Timestamp header
        - request_body: Raw request body bytes
    """
    
    def __init__(self, timestamp_tolerance: int = 300):
        """
        Initialize the HMAC validator.
        
        Args:
            timestamp_tolerance: Maximum age of request in seconds (default: 300)
        """
        self.timestamp_tolerance = timestamp_tolerance
    
    def compute_signature(
        self,
        client_secret: str,
        timestamp: str,
        body: bytes
    ) -> str:
        """
        Compute HMAC-SHA256 signature for a request.
        
        Args:
            client_secret: The tenant's client secret
            timestamp: Unix timestamp as string
            body: Raw request body bytes
            
        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        message = timestamp.encode() + body
        signature = hmac.new(
            client_secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def validate_timestamp(self, timestamp: str) -> bool:
        """
        Validate that the timestamp is within the allowed tolerance.
        
        Args:
            timestamp: Unix timestamp as string
            
        Returns:
            True if timestamp is valid, False otherwise
        """
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
        """
        Validate the provided HMAC signature.
        
        Args:
            client_secret: The tenant's client secret
            timestamp: Unix timestamp from header
            body: Raw request body
            provided_signature: Signature from X-Signature header
            
        Returns:
            True if signature is valid
            
        Raises:
            HMACValidationError: If validation fails
        """
        # Validate timestamp first (prevents replay attacks)
        if not self.validate_timestamp(timestamp):
            raise HMACValidationError(
                f"Request timestamp is too old (tolerance: {self.timestamp_tolerance}s)"
            )
        
        # Compute expected signature
        expected_signature = self.compute_signature(client_secret, timestamp, body)
        
        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise HMACValidationError("Invalid signature")
        
        return True


# Global HMAC validator instance
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
    
    This verifier fetches the JSON Web Key Set (JWKS) from Clerk
    and uses it to verify JWT tokens. The JWKS is cached to reduce
    network requests.
    """
    
    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        cache_ttl: int = 3600
    ):
        """
        Initialize the JWT verifier.
        
        Args:
            jwks_url: URL to fetch JWKS from
            issuer: Expected JWT issuer
            cache_ttl: JWKS cache TTL in seconds
        """
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
        """
        Get JWKS, using cache if available.
        
        Args:
            force_refresh: Force a refresh of the JWKS cache
            
        Returns:
            JWKS dictionary
        """
        current_time = time.time()
        cache_expired = (current_time - self._jwks_fetched_at) > self.cache_ttl
        
        if self._jwks is None or cache_expired or force_refresh:
            self._jwks = await self._fetch_jwks()
            self._jwks_fetched_at = current_time
            logger.debug("jwks_refreshed", url=self.jwks_url)
        
        return self._jwks
    
    def _get_signing_key(self, jwks: dict[str, Any], kid: str) -> dict[str, Any]:
        """
        Get the signing key from JWKS by key ID.
        
        Args:
            jwks: The JWKS dictionary
            kid: Key ID from JWT header
            
        Returns:
            The signing key dictionary
            
        Raises:
            JWTVerificationError: If key is not found
        """
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        raise JWTVerificationError(f"Signing key not found for kid: {kid}")
    
    async def verify_token(
        self,
        token: str,
        audience: str | None = None
    ) -> dict[str, Any]:
        """
        Verify a Clerk JWT token.
        
        Args:
            token: The JWT token to verify
            audience: Optional expected audience
            
        Returns:
            Decoded JWT claims
            
        Raises:
            JWTVerificationError: If verification fails
        """
        try:
            # Decode header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise JWTVerificationError("Missing key ID in JWT header")
            
            # Get JWKS and find signing key
            jwks = await self.get_jwks()
            signing_key = self._get_signing_key(jwks, kid)
            
            # Verify and decode token
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
        """
        Extract user ID from JWT claims.
        
        Clerk uses 'sub' claim for user ID.
        
        Args:
            claims: Decoded JWT claims
            
        Returns:
            User ID string
        """
        user_id = claims.get("sub")
        if not user_id:
            raise JWTVerificationError("Missing user ID in token claims")
        return user_id
    
    def get_org_id_from_claims(self, claims: dict[str, Any]) -> str | None:
        """
        Extract organization ID from JWT claims.
        
        Clerk includes org_id in claims when user has selected an org.
        
        Args:
            claims: Decoded JWT claims
            
        Returns:
            Organization ID or None
        """
        return claims.get("org_id")


# Global JWT verifier instance
jwt_verifier = ClerkJWTVerifier(
    jwks_url=settings.clerk_jwks_url,
    issuer=settings.clerk_jwt_issuer
)


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
        """
        Initialize the sanitizer.
        
        Args:
            allowed_tags: List of allowed HTML tags
            allowed_attributes: Dict of allowed attributes per tag
        """
        self.allowed_tags = allowed_tags or ALLOWED_TAGS
        self.allowed_attributes = allowed_attributes or ALLOWED_ATTRIBUTES
    
    def sanitize_string(self, value: str) -> str:
        """
        Sanitize a string value by stripping HTML/XSS payloads.
        
        Args:
            value: Input string
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value
        
        # Strip HTML tags and attributes
        cleaned = bleach.clean(
            value,
            tags=self.allowed_tags,
            attributes=self.allowed_attributes,
            strip=True
        )
        
        return cleaned
    
    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize all string values in a dictionary.
        
        Args:
            data: Input dictionary
            
        Returns:
            Sanitized dictionary
        """
        sanitized = {}
        for key, value in data.items():
            # Sanitize the key as well
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
        """
        Recursively sanitize all string values in a list.
        
        Args:
            data: Input list
            
        Returns:
            Sanitized list
        """
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
        """
        Sanitize any data type.
        
        Args:
            data: Input data of any type
            
        Returns:
            Sanitized data
        """
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
    Generate and validate request fingerprints for security monitoring.
    
    Fingerprints are hashes of (IP + User-Agent + Tenant-ID) used to detect
    suspicious activity like token theft or session hijacking.
    """
    
    def __init__(self, salt: str | None = None):
        """
        Initialize the fingerprinter.
        
        Args:
            salt: Optional salt for fingerprint hashing
        """
        self.salt = salt or settings.n8n_internal_auth_secret[:16]
    
    def generate_fingerprint(
        self,
        ip_address: str,
        user_agent: str,
        tenant_id: str
    ) -> str:
        """
        Generate a fingerprint hash.
        
        Args:
            ip_address: Client IP address
            user_agent: Client User-Agent header
            tenant_id: Organization tenant ID
            
        Returns:
            SHA-256 hash of the fingerprint components
        """
        # Normalize inputs
        normalized_ip = ip_address.lower().strip()
        normalized_ua = user_agent.lower().strip()
        normalized_tenant = tenant_id.lower().strip()
        
        # Create fingerprint string
        fingerprint_str = f"{self.salt}:{normalized_ip}:{normalized_ua}:{normalized_tenant}"
        
        # Hash the fingerprint
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def compare_fingerprints(
        self,
        fingerprint1: str,
        fingerprint2: str
    ) -> bool:
        """
        Compare two fingerprints securely.
        
        Args:
            fingerprint1: First fingerprint
            fingerprint2: Second fingerprint
            
        Returns:
            True if fingerprints match
        """
        return hmac.compare_digest(fingerprint1, fingerprint2)
    
    def calculate_similarity(
        self,
        stored_fingerprint: str,
        current_fingerprint: str
    ) -> float:
        """
        Calculate similarity between fingerprints (for partial matching).
        
        Note: This is a simplified implementation. In production, you might
        want to store and compare individual components.
        
        Args:
            stored_fingerprint: Previously stored fingerprint
            current_fingerprint: Current request fingerprint
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if self.compare_fingerprints(stored_fingerprint, current_fingerprint):
            return 1.0
        return 0.0


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
        
        Args:
            is_test: Whether this is a test key
            
        Returns:
            Tuple of (full_key, key_prefix, key_hash)
        """
        prefix = self.TEST_PREFIX if is_test else self.LIVE_PREFIX
        random_part = secrets.token_urlsafe(32)
        full_key = f"{prefix}{random_part}"
        key_hash = self.hash_key(full_key)
        key_prefix = full_key[:12]  # Prefix for identification
        
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
        """
        Hash an API key using SHA-256.
        
        Args:
            key: The API key to hash
            
        Returns:
            SHA-256 hash of the key
        """
        return hashlib.sha256(key.encode()).hexdigest()
    
    def verify_key(self, provided_key: str, stored_hash: str) -> bool:
        """
        Verify an API key against its stored hash.
        
        Args:
            provided_key: The API key provided in the request
            stored_hash: The stored hash of the valid key
            
        Returns:
            True if the key is valid
        """
        provided_hash = self.hash_key(provided_key)
        return hmac.compare_digest(provided_hash, stored_hash)
    
    def extract_prefix(self, key: str) -> str:
        """
        Extract the prefix from an API key.
        
        Args:
            key: The full API key
            
        Returns:
            The key prefix
        """
        return key[:12] if len(key) >= 12 else key


# Global API key manager instance
api_key_manager = APIKeyManager()


# =============================================================================
# URL VALIDATION
# =============================================================================


def is_valid_url(url: str) -> bool:
    """
    Validate that a URL is well-formed and uses HTTPS.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid
    """
    try:
        parsed = urlparse(url)
        return all([
            parsed.scheme in ("http", "https"),
            parsed.netloc,
        ])
    except Exception:
        return False


def is_safe_redirect_url(url: str, allowed_hosts: list[str]) -> bool:
    """
    Check if a URL is safe to redirect to.
    
    Args:
        url: URL to check
        allowed_hosts: List of allowed hostnames
        
    Returns:
        True if URL is safe
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc in allowed_hosts
    except Exception:
        return False
