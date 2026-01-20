"""
Tests for security module components.
"""

import hashlib
import hmac
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security import (
    HMACValidationError,
    HMACValidator,
    JWTVerificationError,
    RequestFingerprinter,
    Sanitizer,
    APIKeyManager,
    hmac_validator,
    sanitizer,
    fingerprinter,
    api_key_manager,
)


class TestHMACValidator:
    """Tests for HMAC signature validation."""
    
    def test_compute_signature(self):
        """Test HMAC signature computation."""
        validator = HMACValidator()
        
        client_secret = "test-secret"
        timestamp = "1700000000"
        body = b'{"test": "data"}'
        
        signature = validator.compute_signature(client_secret, timestamp, body)
        
        # Verify it's a valid hex string
        assert len(signature) == 64
        assert all(c in "0123456789abcdef" for c in signature)
        
        # Verify it's deterministic
        signature2 = validator.compute_signature(client_secret, timestamp, body)
        assert signature == signature2
    
    def test_validate_timestamp_valid(self):
        """Test timestamp validation with valid timestamp."""
        validator = HMACValidator(timestamp_tolerance=300)
        
        # Current timestamp should be valid
        current_ts = str(int(time.time()))
        assert validator.validate_timestamp(current_ts) is True
    
    def test_validate_timestamp_expired(self):
        """Test timestamp validation with expired timestamp."""
        validator = HMACValidator(timestamp_tolerance=300)
        
        # Old timestamp should be invalid
        old_ts = str(int(time.time()) - 600)
        assert validator.validate_timestamp(old_ts) is False
    
    def test_validate_timestamp_invalid(self):
        """Test timestamp validation with invalid input."""
        validator = HMACValidator()
        
        assert validator.validate_timestamp("not-a-number") is False
        assert validator.validate_timestamp("") is False
    
    def test_validate_signature_success(self):
        """Test successful signature validation."""
        validator = HMACValidator(timestamp_tolerance=300)
        
        client_secret = "test-secret"
        timestamp = str(int(time.time()))
        body = b'{"test": "data"}'
        
        # Compute correct signature
        signature = validator.compute_signature(client_secret, timestamp, body)
        
        # Validation should pass
        result = validator.validate_signature(client_secret, timestamp, body, signature)
        assert result is True
    
    def test_validate_signature_invalid(self):
        """Test signature validation with wrong signature."""
        validator = HMACValidator(timestamp_tolerance=300)
        
        client_secret = "test-secret"
        timestamp = str(int(time.time()))
        body = b'{"test": "data"}'
        
        with pytest.raises(HMACValidationError, match="Invalid signature"):
            validator.validate_signature(client_secret, timestamp, body, "wrong-signature")
    
    def test_validate_signature_expired_timestamp(self):
        """Test signature validation with expired timestamp."""
        validator = HMACValidator(timestamp_tolerance=300)
        
        client_secret = "test-secret"
        old_timestamp = str(int(time.time()) - 600)
        body = b'{"test": "data"}'
        signature = validator.compute_signature(client_secret, old_timestamp, body)
        
        with pytest.raises(HMACValidationError, match="too old"):
            validator.validate_signature(client_secret, old_timestamp, body, signature)


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
