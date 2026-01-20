from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict

import bleach
from asyncer import asyncify
from fastapi import HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.core.config import Settings


def sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return bleach.clean(value, strip=True)
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_value(val) for key, val in value.items()}
    return value


class SanitizedModel(BaseModel):
    @field_validator("*", mode="before")
    @classmethod
    def _sanitize(cls, value: Any) -> Any:
        return sanitize_value(value)


def parse_bearer_token(authorization_header: str | None) -> str:
    if not authorization_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization header")
    if not authorization_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization header")
    return authorization_header.split(" ", 1)[1].strip()


def validate_hmac_signature(
    *,
    timestamp: str | None,
    body: bytes,
    signature: str | None,
    secret: str,
    max_age_seconds: int,
) -> None:
    if not timestamp or not signature:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing HMAC headers")

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid timestamp") from exc

    now = int(time.time())
    if abs(now - timestamp_int) > max_age_seconds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Request timestamp expired")

    payload = f"{timestamp}".encode() + body
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid request signature")


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def build_fingerprint(ip: str, user_agent: str, tenant_id: str) -> str:
    raw = f"{ip}|{user_agent}|{tenant_id}".encode()
    return hashlib.sha256(raw).hexdigest()


def _normalize_claims(claims: Any) -> Dict[str, Any]:
    if isinstance(claims, dict):
        return claims
    if hasattr(claims, "to_dict"):
        return claims.to_dict()
    if hasattr(claims, "dict"):
        return claims.dict()
    try:
        return dict(claims)
    except Exception:
        return {"raw": str(claims)}


async def decode_clerk_jwt(token: str, settings: Settings) -> Dict[str, Any]:
    def _verify_token() -> Any:
        from clerk_backend_api.jwks import verify_token

        return verify_token(
            token,
            jwks_url=str(settings.clerk_jwks_url),
            issuer=settings.clerk_issuer,
            audience=settings.clerk_audience,
        )

    try:
        claims = await asyncify(_verify_token)()
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    return _normalize_claims(claims)


class UserContext(BaseModel):
    user_id: str
    token: str
    claims: Dict[str, Any]
    email: str | None = None
    session_id: str | None = None


async def get_current_user(request: Request) -> UserContext:
    settings: Settings = request.app.state.settings
    authorization_header = request.headers.get("authorization")
    token = parse_bearer_token(authorization_header)

    claims = request.state.jwt_claims if hasattr(request.state, "jwt_claims") else None
    if not claims:
        claims = await decode_clerk_jwt(token, settings)

    user_id = claims.get("sub") or claims.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

    return UserContext(
        user_id=str(user_id),
        token=token,
        claims=claims,
        email=claims.get("email"),
        session_id=claims.get("sid"),
    )
