import hashlib
import hmac
import time

import pytest
from fastapi import HTTPException

from app.core.security import build_fingerprint, sanitize_value, validate_hmac_signature
from app.models.schemas import ExecuteRequest


def test_validate_hmac_signature_ok():
    timestamp = str(int(time.time()))
    body = b'{"hello":"world"}'
    secret = "super-secret"
    signature = hmac.new(secret.encode(), timestamp.encode() + body, hashlib.sha256).hexdigest()

    validate_hmac_signature(
        timestamp=timestamp,
        body=body,
        signature=signature,
        secret=secret,
        max_age_seconds=300,
    )


def test_validate_hmac_signature_bad():
    timestamp = str(int(time.time()))
    body = b"{}"

    with pytest.raises(HTTPException):
        validate_hmac_signature(
            timestamp=timestamp,
            body=body,
            signature="bad-signature",
            secret="super-secret",
            max_age_seconds=300,
        )


def test_sanitize_value():
    value = sanitize_value("<script>alert(1)</script>")
    assert "<script>" not in value

    model = ExecuteRequest(payload={"text": "<img src=x onerror=alert(1)>"})
    assert "<" not in model.payload["text"]


def test_fingerprint_is_deterministic():
    fingerprint = build_fingerprint("127.0.0.1", "agent", "tenant_a")
    assert fingerprint == build_fingerprint("127.0.0.1", "agent", "tenant_a")
