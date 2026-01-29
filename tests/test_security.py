"""
Tests for security module components.
"""

import hashlib
import hmac
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security import (
    JWTVerificationError,
    RequestFingerprinter,
    Sanitizer,
    APIKeyManager,
    TimestampValidator,
    sanitizer,
    fingerprinter,
    api_key_manager,
    timestamp_validator,
)


class TestTimestampValidator:
    """Tests for timestamp validation (replay protection)."""
    
    def test_validate_timestamp_valid(self):
        """Test timestamp validation with valid timestamp."""
        validator = TimestampValidator(tolerance_seconds=300)
        
        # Current timestamp should be valid
        current_ts = str(int(time.time()))
        assert validator.is_valid(current_ts) is True
    
    def test_validate_timestamp_expired(self):
        """Test timestamp validation with expired timestamp."""
        validator = TimestampValidator(tolerance_seconds=300)
        
        # Old timestamp should be invalid
        old_ts = str(int(time.time()) - 600)
        assert validator.is_valid(old_ts) is False
    
    def test_validate_timestamp_invalid_format(self):
        """Test timestamp validation with invalid input."""
        validator = TimestampValidator(tolerance_seconds=300)
        
        assert validator.is_valid("not-a-number") is False
        assert validator.is_valid("") is False
        assert validator.is_valid(None) is False
    
    def test_validate_timestamp_integer_input(self):
        """Test timestamp validation with integer input."""
        validator = TimestampValidator(tolerance_seconds=300)
        
        # Integer timestamp should work
        current_ts = int(time.time())
        assert validator.is_valid(current_ts) is True
    
    def test_global_validator(self):
        """Test the global timestamp validator instance."""
        current_ts = str(int(time.time()))
        assert timestamp_validator.is_valid(current_ts) is True


class TestSanitizer:
    """Tests for input sanitization."""
    
    def test_sanitize_string_strips_html(self):
        """Test that HTML tags are stripped."""
        result = sanitizer.sanitize_string("<script>alert('xss')</script>Hello")
        assert "<script>" not in result
        assert "Hello" in result
    
    def test_sanitize_string_strips_attributes(self):
        """Test that HTML attributes are stripped."""
        result = sanitizer.sanitize_string('<a href="javascript:alert()">link</a>')
        assert "javascript:" not in result
        assert "href" not in result
    
    def test_sanitize_string_preserves_text(self):
        """Test that regular text is preserved."""
        text = "Hello, this is normal text! 123 @#$"
        result = sanitizer.sanitize_string(text)
        assert result == text
    
    def test_sanitize_dict(self):
        """Test dictionary sanitization."""
        data = {
            "name": "<script>bad</script>Good Name",
            "nested": {
                "value": "<img onerror='alert()'>test"
            }
        }
        
        result = sanitizer.sanitize_dict(data)
        
        assert "<script>" not in result["name"]
        assert "Good Name" in result["name"]
        assert "<img" not in result["nested"]["value"]
    
    def test_sanitize_list(self):
        """Test list sanitization."""
        data = ["<b>bold</b>", {"key": "<script>x</script>value"}]
        
        result = sanitizer.sanitize_list(data)
        
        assert "<b>" not in result[0]
        assert "<script>" not in result[1]["key"]
    
    def test_sanitize_non_string_passthrough(self):
        """Test that non-string values pass through unchanged."""
        assert sanitizer.sanitize_string(123) == 123
        assert sanitizer.sanitize_string(None) is None


class TestRequestFingerprinter:
    """Tests for request fingerprinting."""
    
    def test_generate_fingerprint(self):
        """Test fingerprint generation."""
        fp = fingerprinter.generate_fingerprint(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            tenant_id="test-tenant"
        )
        
        # Should be a SHA-256 hash
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)
    
    def test_fingerprint_deterministic(self):
        """Test that same inputs produce same fingerprint."""
        fp1 = fingerprinter.generate_fingerprint(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            tenant_id="test-tenant"
        )
        fp2 = fingerprinter.generate_fingerprint(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            tenant_id="test-tenant"
        )
        
        assert fp1 == fp2
    
    def test_fingerprint_different_inputs(self):
        """Test that different inputs produce different fingerprints."""
        fp1 = fingerprinter.generate_fingerprint("192.168.1.1", "Mozilla/5.0", "tenant-1")
        fp2 = fingerprinter.generate_fingerprint("192.168.1.2", "Mozilla/5.0", "tenant-1")
        
        assert fp1 != fp2
    
    def test_compare_fingerprints(self):
        """Test fingerprint comparison."""
        fp = fingerprinter.generate_fingerprint("192.168.1.1", "Mozilla/5.0", "tenant")
        
        assert fingerprinter.compare_fingerprints(fp, fp) is True
        assert fingerprinter.compare_fingerprints(fp, "different") is False
    
    def test_fingerprint_case_insensitive(self):
        """Test that fingerprinting normalizes case."""
        fp1 = fingerprinter.generate_fingerprint("192.168.1.1", "Mozilla/5.0", "TENANT")
        fp2 = fingerprinter.generate_fingerprint("192.168.1.1", "Mozilla/5.0", "tenant")
        
        assert fp1 == fp2


class TestAPIKeyManager:
    """Tests for API key management."""
    
    def test_generate_api_key_live(self):
        """Test live API key generation."""
        full_key, prefix, key_hash = api_key_manager.generate_api_key(is_test=False)
        
        assert full_key.startswith("gw_live_")
        assert prefix == full_key[:12]
        assert len(key_hash) == 64  # SHA-256
    
    def test_generate_api_key_test(self):
        """Test test API key generation."""
        full_key, prefix, key_hash = api_key_manager.generate_api_key(is_test=True)
        
        assert full_key.startswith("gw_test_")
    
    def test_generate_client_secret(self):
        """Test client secret generation."""
        secret, secret_hash = api_key_manager.generate_client_secret()
        
        assert len(secret) > 32
        assert len(secret_hash) == 64
    
    def test_verify_key_correct(self):
        """Test API key verification with correct key."""
        full_key, _, key_hash = api_key_manager.generate_api_key()
        
        assert api_key_manager.verify_key(full_key, key_hash) is True
    
    def test_verify_key_incorrect(self):
        """Test API key verification with incorrect key."""
        full_key, _, key_hash = api_key_manager.generate_api_key()
        
        assert api_key_manager.verify_key("wrong-key", key_hash) is False
    
    def test_extract_prefix(self):
        """Test prefix extraction."""
        prefix = api_key_manager.extract_prefix("gw_live_abc123def456")
        
        assert prefix == "gw_live_abc1"
    
    def test_extract_prefix_short_key(self):
        """Test prefix extraction with short key."""
        prefix = api_key_manager.extract_prefix("short")
        
        assert prefix == "short"
    
    def test_hash_key_deterministic(self):
        """Test that hashing is deterministic."""
        key = "test-api-key-123"
        hash1 = api_key_manager.hash_key(key)
        hash2 = api_key_manager.hash_key(key)
        
        assert hash1 == hash2
        assert len(hash1) == 64


class TestJWTVerificationError:
    """Tests for JWT verification error handling."""
    
    def test_exception_message(self):
        """Test exception message is preserved."""
        error = JWTVerificationError("Token expired")
        assert str(error) == "Token expired"
    
    def test_exception_inheritance(self):
        """Test exception is an Exception subclass."""
        error = JWTVerificationError("Test error")
        assert isinstance(error, Exception)
