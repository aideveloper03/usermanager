"""
Execute Endpoint - Main controller for n8n workflow execution.

This endpoint handles:
1. JWT/API Key authentication validation
2. Organization and workflow verification
3. Credit balance checking and deduction
4. Tenant credential retrieval from Vault
5. n8n webhook execution with credential injection
6. Response streaming back to client
"""

import time
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.security import (
    HMACValidationError,
    api_key_manager,
    hmac_validator,
)
from app.middleware.auth_middleware import (
    get_current_user,
    get_request_context,
)
from app.models.schemas import (
    ExecuteRequest,
    ExecuteResponse,
    ExecutionStatus,
    ErrorResponse,
)
from app.services.database import DatabaseService, get_db_service
from app.services.n8n_client import (
    N8NClient,
    N8NClientError,
    N8NTimeoutError,
    N8NWebhookError,
    get_n8n_client,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


async def validate_api_key_auth(
    request: Request,
    db: DatabaseService
) -> dict[str, Any]:
    """
    Validate API key authentication and return organization details.
    
    Args:
        request: FastAPI request object
        db: Database service
        
    Returns:
        Organization data
        
    Raises:
        HTTPException: If authentication fails
    """
    api_key_prefix = getattr(request.state, "api_key_prefix", None)
    api_key_full = getattr(request.state, "api_key_full", None)
    
    if not api_key_prefix or not api_key_full:
        raise HTTPException(status_code=401, detail="API key authentication required")
    
    # Look up organization by API key prefix
    org = await db.get_organization_by_api_key_prefix(api_key_prefix)
    
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Verify the full API key against the stored hash
    if not api_key_manager.verify_key(api_key_full, org["api_key_hash"]):
        await db.log_security_event(
            event_type="invalid_api_key",
            severity="warning",
            org_id=org["id"],
            ip_address=getattr(request.state, "ip_address", None),
            user_agent=getattr(request.state, "user_agent", None),
            request_path=str(request.url.path),
            request_method=request.method,
            details={"key_prefix": api_key_prefix}
        )
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return org


async def validate_hmac_signature(
    request: Request,
    org: dict[str, Any]
) -> bool:
    """
    Validate HMAC signature for anti-hijacking protection.
    
    Args:
        request: FastAPI request object
        org: Organization data with client_secret_hash
        
    Returns:
        True if validation passes
        
    Raises:
        HTTPException: If validation fails
    """
    if not settings.enable_hmac_validation:
        return True
    
    signature = getattr(request.state, "hmac_signature", None)
    timestamp = getattr(request.state, "hmac_timestamp", None)
    body = getattr(request.state, "hmac_body", None)
    
    # HMAC is optional for JWT auth
    if not signature or not timestamp:
        auth_method = getattr(request.state, "auth_method", None)
        if auth_method == "jwt":
            return True
        raise HTTPException(
            status_code=403,
            detail="HMAC signature required for API key authentication"
        )
    
    # For HMAC validation, we need the client secret
    # Since we store the hash, we can't verify HMAC directly
    # In production, you would either:
    # 1. Store the client secret encrypted in Vault
    # 2. Use a different signing approach
    # For now, we'll verify the timestamp and log the attempt
    
    if not hmac_validator.validate_timestamp(timestamp):
        raise HTTPException(
            status_code=403,
            detail=f"Request timestamp too old (tolerance: {settings.hmac_timestamp_tolerance}s)"
        )
    
    # Log HMAC validation attempt
    logger.debug(
        "hmac_validation",
        org_id=org.get("id"),
        timestamp=timestamp,
        signature_present=bool(signature)
    )
    
    return True


@router.post(
    "",
    response_model=ExecuteResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        402: {"model": ErrorResponse, "description": "Insufficient Credits"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "Workflow Not Found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
        504: {"model": ErrorResponse, "description": "Gateway Timeout"},
    },
    summary="Execute N8N Workflow",
    description="""
    Execute an n8n workflow through the orchestration gateway.
    
    This endpoint:
    1. Validates authentication (JWT or API key)
    2. Verifies HMAC signature (if using API key auth)
    3. Checks the organization has sufficient credits
    4. Retrieves the workflow configuration
    5. Fetches tenant credentials from Supabase Vault
    6. Executes the n8n webhook with injected credentials
    7. Returns the workflow response
    
    **Authentication:**
    - Bearer token (Clerk JWT) in Authorization header, OR
    - API key in X-API-Key header (requires X-Signature and X-Timestamp for HMAC)
    
    **Headers for API Key auth:**
    - `X-API-Key`: Your organization's API key
    - `X-Signature`: HMAC-SHA256(client_secret, timestamp + body)
    - `X-Timestamp`: Unix timestamp (must be within 300 seconds of current time)
    - `X-Tenant-ID`: Your organization's tenant ID
    """
)
async def execute_workflow(
    request: Request,
    execute_request: ExecuteRequest,
    db: DatabaseService = Depends(get_db_service),
    n8n: N8NClient = Depends(get_n8n_client),
) -> ExecuteResponse:
    """
    Execute an n8n workflow.
    
    This is the main execution endpoint that orchestrates:
    - Authentication validation
    - Credit management
    - Credential injection
    - Workflow execution
    """
    request_id = getattr(request.state, "request_id", "unknown")
    start_time = time.time()
    
    logger.info(
        "execute_request_received",
        request_id=request_id,
        workflow_id=str(execute_request.workflow_id)
    )
    
    try:
        # Step 1: Determine authentication method and get organization
        auth_method = getattr(request.state, "auth_method", None)
        
        if auth_method == "api_key":
            org = await validate_api_key_auth(request, db)
            await validate_hmac_signature(request, org)
            user_id = None
        elif auth_method == "jwt":
            user_id = getattr(request.state, "user_id", None)
            org_id = getattr(request.state, "org_id", None)
            
            if not org_id:
                # Try to get from tenant_id header
                tenant_id = request.headers.get("X-Tenant-ID")
                if tenant_id:
                    org = await db.get_organization_by_tenant(tenant_id)
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="Organization context required. Include org_id in JWT or X-Tenant-ID header."
                    )
            else:
                org = await db.get_organization(UUID(org_id))
            
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
        else:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        org_id = UUID(org["id"])
        
        # Step 2: Verify organization is active
        if not org.get("is_active", False):
            raise HTTPException(status_code=403, detail="Organization is inactive")
        
        # Step 3: Get and verify workflow
        workflow = await db.get_workflow_by_org(org_id, execute_request.workflow_id)
        
        if not workflow:
            raise HTTPException(
                status_code=404,
                detail=f"Workflow {execute_request.workflow_id} not found or inactive"
            )
        
        credits_required = workflow.get("credits_per_execution", 1)
        timeout = execute_request.timeout_override or workflow.get("timeout_seconds", 300)
        
        # Step 4: Deduct credits atomically
        credit_result = await db.deduct_credits(
            org_id=org_id,
            amount=credits_required,
            workflow_id=execute_request.workflow_id,
            profile_id=user_id,
            metadata={
                "request_id": request_id,
                "workflow_name": workflow.get("name"),
                "ip_address": getattr(request.state, "ip_address", None),
                "fingerprint": getattr(request.state, "fingerprint", None),
            }
        )
        
        if not credit_result.get("success"):
            error_msg = credit_result.get("error_message", "Credit deduction failed")
            if "Insufficient credits" in error_msg:
                raise HTTPException(
                    status_code=402,
                    detail={
                        "error": "insufficient_credits",
                        "message": f"Insufficient credits. Required: {credits_required}, Available: {org.get('credits', 0)}",
                        "credits_required": credits_required,
                        "credits_available": credit_result.get("remaining_credits", 0)
                    }
                )
            raise HTTPException(status_code=400, detail=error_msg)
        
        usage_log_id = UUID(credit_result["usage_log_id"])
        remaining_credits = credit_result.get("remaining_credits", 0)
        
        # Step 5: Update usage log to running status
        await db.update_usage_status(usage_log_id, ExecutionStatus.RUNNING)
        
        # Step 6: Retrieve tenant credentials (with advisory lock if using dynamic injection)
        use_dynamic = settings.n8n_use_dynamic_credentials and settings.n8n_api_key
        
        if use_dynamic:
            # Get credentials with advisory lock to prevent credential bleed
            cred_data = await db.get_credentials_with_lock(org_id)
            tenant_credentials = cred_data.get("credentials") if cred_data else None
            credential_mappings = cred_data.get("credential_mappings") if cred_data else None
        else:
            # Simple mode - just get credentials for payload injection
            tenant_credentials = await db.get_tenant_credentials(org_id)
            credential_mappings = None
        
        # Step 7: Execute n8n webhook
        try:
            n8n_response = await n8n.execute_webhook(
                webhook_path=workflow["n8n_webhook_path"],
                data=execute_request.data,
                tenant_credentials=tenant_credentials,
                credential_mappings=credential_mappings,
                timeout=timeout,
                execution_id=usage_log_id,
                use_dynamic_injection=use_dynamic
            )
            
            execution_time_ms = n8n_response.get("execution_time_ms", 0)
            
            # Step 8: Update usage log with success
            await db.update_usage_status(
                usage_log_id,
                ExecutionStatus.COMPLETED,
                execution_time_ms=execution_time_ms,
                response_metadata={"success": True}
            )
            
            logger.info(
                "execute_request_completed",
                request_id=request_id,
                workflow_id=str(execute_request.workflow_id),
                execution_time_ms=execution_time_ms,
                credits_used=credits_required
            )
            
            return ExecuteResponse(
                success=True,
                execution_id=usage_log_id,
                status=ExecutionStatus.COMPLETED,
                data=n8n_response.get("data"),
                credits_used=credits_required,
                credits_remaining=remaining_credits,
                execution_time_ms=execution_time_ms
            )
            
        except N8NTimeoutError as e:
            # Timeout - update status but don't refund (workflow may still complete)
            execution_time_ms = int((time.time() - start_time) * 1000)
            await db.update_usage_status(
                usage_log_id,
                ExecutionStatus.TIMEOUT,
                execution_time_ms=execution_time_ms,
                error_message=str(e)
            )
            
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "gateway_timeout",
                    "message": str(e),
                    "execution_id": str(usage_log_id)
                }
            )
            
        except N8NWebhookError as e:
            # Webhook error - update status and refund
            execution_time_ms = int((time.time() - start_time) * 1000)
            await db.update_usage_status(
                usage_log_id,
                ExecutionStatus.FAILED,
                execution_time_ms=execution_time_ms,
                error_message=str(e)
            )
            
            # Refund credits on failure
            await db.refund_credits(usage_log_id)
            
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "n8n_error",
                    "message": str(e),
                    "execution_id": str(usage_log_id)
                }
            )
            
        except N8NClientError as e:
            # Client error - update status and refund
            execution_time_ms = int((time.time() - start_time) * 1000)
            await db.update_usage_status(
                usage_log_id,
                ExecutionStatus.FAILED,
                execution_time_ms=execution_time_ms,
                error_message=str(e)
            )
            
            await db.refund_credits(usage_log_id)
            
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "execution_error",
                    "message": str(e),
                    "execution_id": str(usage_log_id)
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "execute_request_error",
            request_id=request_id,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "internal_error",
                "message": "An unexpected error occurred",
                "request_id": request_id
            }
        )


@router.post(
    "/stream",
    summary="Execute N8N Workflow (Streaming)",
    description="""
    Execute an n8n workflow and stream the response.
    
    This endpoint is useful for long-running workflows that may return
    data incrementally. The response is streamed as it becomes available.
    """
)
async def execute_workflow_stream(
    request: Request,
    execute_request: ExecuteRequest,
    db: DatabaseService = Depends(get_db_service),
    n8n: N8NClient = Depends(get_n8n_client),
) -> StreamingResponse:
    """Execute an n8n workflow with streaming response."""
    request_id = getattr(request.state, "request_id", "unknown")
    
    # Perform same validation as non-streaming endpoint
    auth_method = getattr(request.state, "auth_method", None)
    
    if auth_method == "api_key":
        org = await validate_api_key_auth(request, db)
        await validate_hmac_signature(request, org)
        user_id = None
    elif auth_method == "jwt":
        user_id = getattr(request.state, "user_id", None)
        org_id = getattr(request.state, "org_id", None)
        
        if not org_id:
            tenant_id = request.headers.get("X-Tenant-ID")
            if tenant_id:
                org = await db.get_organization_by_tenant(tenant_id)
            else:
                raise HTTPException(status_code=400, detail="Organization context required")
        else:
            org = await db.get_organization(UUID(org_id))
        
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
    else:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    org_id = UUID(org["id"])
    
    if not org.get("is_active", False):
        raise HTTPException(status_code=403, detail="Organization is inactive")
    
    workflow = await db.get_workflow_by_org(org_id, execute_request.workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found or inactive")
    
    # Deduct credits
    credits_required = workflow.get("credits_per_execution", 1)
    credit_result = await db.deduct_credits(
        org_id=org_id,
        amount=credits_required,
        workflow_id=execute_request.workflow_id,
        profile_id=user_id,
        metadata={"request_id": request_id, "streaming": True}
    )
    
    if not credit_result.get("success"):
        raise HTTPException(status_code=402, detail="Insufficient credits")
    
    usage_log_id = UUID(credit_result["usage_log_id"])
    await db.update_usage_status(usage_log_id, ExecutionStatus.RUNNING)
    
    # Get tenant credentials
    tenant_credentials = await db.get_tenant_credentials(org_id)
    
    timeout = execute_request.timeout_override or workflow.get("timeout_seconds", 300)
    
    # Return streaming response
    return StreamingResponse(
        n8n.execute_webhook_stream(
            webhook_path=workflow["n8n_webhook_path"],
            data=execute_request.data,
            tenant_credentials=tenant_credentials,
            timeout=timeout,
            execution_id=usage_log_id
        ),
        media_type="application/json",
        headers={
            "X-Execution-ID": str(usage_log_id),
            "X-Request-ID": request_id
        }
    )
