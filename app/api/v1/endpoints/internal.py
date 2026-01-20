"""
Internal Endpoints for n8n Callbacks.

These endpoints are used by n8n workflows to report status back to the gateway.
They require the internal authentication secret.
"""

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException

from app.core.config import settings
from app.models.schemas import (
    ExecutionStatus,
    InternalLogRequest,
    N8NErrorCallback,
)
from app.services.database import DatabaseService, get_db_service

logger = structlog.get_logger(__name__)
router = APIRouter()


async def verify_internal_auth(
    x_n8n_internal_auth: str = Header(..., alias="X-N8N-Internal-Auth")
) -> bool:
    """Verify the internal authentication header from n8n."""
    if x_n8n_internal_auth != settings.n8n_internal_auth_secret:
        logger.warning("invalid_internal_auth_attempt")
        raise HTTPException(status_code=401, detail="Invalid internal authentication")
    return True


@router.post(
    "/log-error",
    status_code=204,
    summary="Log Error from n8n",
    description="""
    Callback endpoint for n8n error workflows to report failures.
    
    This endpoint is called by n8n when a workflow fails, allowing the
    gateway to update the usage log status and potentially refund credits.
    
    Requires the X-N8N-Internal-Auth header.
    """
)
async def log_error(
    error_data: N8NErrorCallback,
    _: bool = Depends(verify_internal_auth),
    db: DatabaseService = Depends(get_db_service),
) -> None:
    """Handle error callback from n8n."""
    logger.warning(
        "n8n_error_callback",
        workflow_id=error_data.workflow_id,
        execution_id=error_data.execution_id,
        error=error_data.error_message[:200]  # Truncate for logging
    )
    
    # Try to find and update the usage log based on n8n execution_id
    # This requires storing the n8n execution ID in the usage log metadata
    # For now, we just log the error
    
    await db.log_security_event(
        event_type="n8n_workflow_error",
        severity="warning",
        details={
            "n8n_workflow_id": error_data.workflow_id,
            "n8n_execution_id": error_data.execution_id,
            "error_message": error_data.error_message[:500],
            "timestamp": error_data.timestamp.isoformat(),
        }
    )


@router.post(
    "/update-status",
    status_code=204,
    summary="Update Execution Status",
    description="""
    Update the status of a workflow execution.
    
    This endpoint is called by n8n workflows to update execution status,
    particularly for long-running async workflows.
    
    Requires the X-N8N-Internal-Auth header.
    """
)
async def update_status(
    request: InternalLogRequest,
    _: bool = Depends(verify_internal_auth),
    db: DatabaseService = Depends(get_db_service),
) -> None:
    """Update usage log status from n8n callback."""
    success = await db.update_usage_status(
        usage_log_id=request.usage_log_id,
        status=request.status,
        execution_time_ms=request.execution_time_ms,
        error_message=request.error_message,
        response_metadata=request.response_metadata
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Usage log not found")
    
    # If status is failed, refund credits
    if request.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT):
        refund_result = await db.refund_credits(request.usage_log_id)
        if refund_result.get("success"):
            logger.info(
                "credits_refunded_via_callback",
                usage_log_id=str(request.usage_log_id),
                amount=refund_result.get("refunded_amount")
            )
    
    logger.info(
        "execution_status_updated",
        usage_log_id=str(request.usage_log_id),
        status=request.status.value
    )
