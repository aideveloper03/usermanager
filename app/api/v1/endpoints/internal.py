from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.core.config import Settings
from app.models.schemas import ErrorLogRequest

router = APIRouter()


@router.post("/internal/log-error")
async def log_n8n_error(payload: ErrorLogRequest, request: Request):
    settings: Settings = request.app.state.settings
    internal_secret = request.headers.get("x-n8n-internal-auth")
    if internal_secret != settings.n8n_internal_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal auth")

    supabase_admin = request.app.state.supabase_admin
    response = await supabase_admin.from_("usage_logs").insert(
        {
            "org_id": payload.org_id,
            "credits_used": 0,
            "status": payload.status,
            "metadata": {
                "workflow_id": payload.workflow_id,
                "error_message": payload.error_message,
                **payload.metadata,
            },
        }
    ).execute()

    if getattr(response, "error", None):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record error: {response.error.message}",
        )

    return {"status": "logged"}
