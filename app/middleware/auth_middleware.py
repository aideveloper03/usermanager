from __future__ import annotations

from typing import Iterable

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import Settings
from app.core.security import (
    build_fingerprint,
    decode_clerk_jwt,
    get_client_ip,
    parse_bearer_token,
    validate_hmac_signature,
)


EXEMPT_PATH_PREFIXES: Iterable[str] = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/api/v1/internal",
)


class AuthHijackMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or request.url.path.startswith(tuple(EXEMPT_PATH_PREFIXES)):
            return await call_next(request)

        tenant_id = request.headers.get("x-tenant-id")
        if not tenant_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing X-Tenant-ID header")

        body = await request.body()
        request.state.raw_body = body
        request._body = body

        async def receive() -> dict:
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive

        supabase_admin = request.app.state.supabase_admin
        org_response = (
            await supabase_admin.from_("organizations")
            .select("id")
            .eq("tenant_id", tenant_id)
            .single()
            .execute()
        )
        if getattr(org_response, "error", None):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to resolve tenant: {org_response.error.message}",
            )
        if not org_response.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

        org_id = org_response.data["id"]
        request.state.org_id = org_id

        secrets_response = (
            await supabase_admin.rpc("fn_get_tenant_secrets", {"p_org_id": org_id}).execute()
        )
        if getattr(secrets_response, "error", None):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to resolve tenant secrets: {secrets_response.error.message}",
            )
        if not secrets_response.data:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Tenant secrets missing")

        tenant_secrets = secrets_response.data
        request.state.tenant_secrets = tenant_secrets

        client_secret = tenant_secrets.get("client_secret")
        if not client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant client_secret not configured",
            )

        validate_hmac_signature(
            timestamp=request.headers.get("x-timestamp"),
            body=body,
            signature=request.headers.get("x-signature"),
            secret=client_secret,
            max_age_seconds=self.settings.hmac_max_age_seconds,
        )

        token = parse_bearer_token(request.headers.get("authorization"))
        claims = await decode_clerk_jwt(token, self.settings)
        request.state.jwt_claims = claims
        request.state.user_id = claims.get("sub") or claims.get("user_id")

        user_agent = request.headers.get("user-agent", "unknown")
        fingerprint = build_fingerprint(get_client_ip(request), user_agent, tenant_id)
        request.state.fingerprint = fingerprint

        if request.state.user_id:
            previous = (
                await supabase_admin.from_("security_logs")
                .select("fingerprint_hash")
                .eq("org_id", org_id)
                .eq("user_id", request.state.user_id)
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            )
            previous_hash = None
            if previous.data:
                previous_hash = previous.data[0].get("fingerprint_hash")

            if previous_hash is None or previous_hash != fingerprint:
                status_label = "baseline" if previous_hash is None else "suspicious"
                await supabase_admin.from_("security_logs").insert(
                    {
                        "org_id": org_id,
                        "user_id": request.state.user_id,
                        "fingerprint_hash": fingerprint,
                        "status": status_label,
                        "metadata": {
                            "ip": get_client_ip(request),
                            "user_agent": user_agent,
                            "tenant_id": tenant_id,
                        },
                    }
                ).execute()

        return await call_next(request)
