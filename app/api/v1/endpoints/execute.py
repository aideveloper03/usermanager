from __future__ import annotations

from typing import Any, Dict

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import Settings
from app.core.limiter import limiter, settings as limiter_settings
from app.core.security import UserContext, get_current_user
from app.db.supabase import create_user_client
from app.models.schemas import ExecuteRequest

router = APIRouter()


def _handle_supabase_error(response: Any, detail: str) -> None:
    if getattr(response, "error", None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{detail}: {response.error.message}",
        )


@router.post("/execute")
@limiter.limit(limiter_settings.rate_limit)
async def execute_workflow(
    payload: ExecuteRequest,
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    settings: Settings = request.app.state.settings
    tenant_id = request.headers.get("x-tenant-id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing X-Tenant-ID header")

    supabase_user = await create_user_client(settings, user.token)
    org_response = (
        await supabase_user.from_("organizations")
        .select("id, credits")
        .eq("tenant_id", tenant_id)
        .eq("owner_id", user.user_id)
        .single()
        .execute()
    )
    _handle_supabase_error(org_response, "Failed to load organization")
    if not org_response.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    org_id = org_response.data["id"]

    credits_response = await supabase_user.rpc(
        "fn_deduct_credits",
        {
            "p_org_id": org_id,
            "p_credits": payload.credits,
            "p_metadata": {"path": str(request.url.path), "tenant_id": tenant_id},
        },
    ).execute()
    _handle_supabase_error(credits_response, "Credit deduction failed")

    tenant_secrets: Dict[str, Any] = {}
    if hasattr(request.state, "tenant_secrets") and request.state.tenant_secrets:
        tenant_secrets = dict(request.state.tenant_secrets)
    else:
        secrets_response = (
            await request.app.state.supabase_admin.rpc("fn_get_tenant_secrets", {"p_org_id": org_id}).execute()
        )
        _handle_supabase_error(secrets_response, "Failed to load tenant secrets")
        tenant_secrets = secrets_response.data or {}

    tenant_secrets.pop("client_secret", None)
    n8n_payload = {"data": payload.payload, "secrets": tenant_secrets}

    n8n_headers = {
        "X-N8N-Internal-Auth": settings.n8n_internal_secret,
        "Content-Type": "application/json",
    }

    client: httpx.AsyncClient = request.app.state.httpx
    stream_context = client.stream(
        "POST",
        str(settings.n8n_webhook_url),
        headers=n8n_headers,
        json=n8n_payload,
        timeout=settings.request_timeout_seconds,
    )
    response = await stream_context.__aenter__()

    async def _iter_body():
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        finally:
            await stream_context.__aexit__(None, None, None)

    return StreamingResponse(
        _iter_body(),
        status_code=response.status_code,
        media_type=response.headers.get("content-type"),
    )
