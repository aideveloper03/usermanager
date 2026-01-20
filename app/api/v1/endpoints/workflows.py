"""
Workflow Management Endpoints.

Provides CRUD operations for workflows including:
- Workflow registration
- Workflow configuration
- Workflow activation/deactivation
"""

from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

from app.middleware.auth_middleware import get_current_user
from app.models.schemas import (
    WorkflowCreate,
    WorkflowResponse,
    WorkflowUpdate,
)
from app.services.database import DatabaseService, get_db_service

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=WorkflowResponse,
    status_code=201,
    summary="Create Workflow",
    description="""
    Register a new n8n workflow with the gateway.
    
    This links an n8n workflow to your organization for execution via the API.
    Requires admin or owner role.
    """
)
async def create_workflow(
    workflow_data: WorkflowCreate,
    org_id: UUID,  # Query parameter for organization
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> WorkflowResponse:
    """Create a new workflow."""
    # Verify user has admin access to the organization
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next((o for o in user_orgs if str(o["id"]) == str(org_id)), None)
    
    if not user_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if user_org.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Create workflow
    workflow = await db.create_workflow({
        "organization_id": str(org_id),
        "name": workflow_data.name,
        "description": workflow_data.description,
        "n8n_workflow_id": workflow_data.n8n_workflow_id,
        "n8n_webhook_path": workflow_data.n8n_webhook_path,
        "is_active": workflow_data.is_active,
        "credits_per_execution": workflow_data.credits_per_execution,
        "timeout_seconds": workflow_data.timeout_seconds,
        "settings": workflow_data.settings,
    })
    
    logger.info(
        "workflow_created",
        workflow_id=workflow["id"],
        org_id=str(org_id),
        n8n_workflow_id=workflow_data.n8n_workflow_id
    )
    
    return WorkflowResponse(**workflow)


@router.get(
    "",
    response_model=list[WorkflowResponse],
    summary="List Workflows",
    description="Get all workflows for an organization."
)
async def list_workflows(
    org_id: UUID,
    include_inactive: bool = False,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> list[WorkflowResponse]:
    """List workflows for an organization."""
    # Verify access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    if not any(str(o["id"]) == str(org_id) for o in user_orgs):
        raise HTTPException(status_code=403, detail="Access denied")
    
    workflows = await db.get_organization_workflows(org_id, active_only=not include_inactive)
    
    return [WorkflowResponse(**w) for w in workflows]


@router.get(
    "/{workflow_id}",
    response_model=WorkflowResponse,
    summary="Get Workflow",
    description="Get workflow details by ID."
)
async def get_workflow(
    workflow_id: UUID,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> WorkflowResponse:
    """Get workflow by ID."""
    workflow = await db.get_workflow(workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    # Verify access to the organization
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    if not any(str(o["id"]) == workflow["organization_id"] for o in user_orgs):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return WorkflowResponse(**workflow)


@router.patch(
    "/{workflow_id}",
    response_model=WorkflowResponse,
    summary="Update Workflow",
    description="Update workflow configuration. Requires admin or owner role."
)
async def update_workflow(
    workflow_id: UUID,
    updates: WorkflowUpdate,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> WorkflowResponse:
    """Update workflow configuration."""
    workflow = await db.get_workflow(workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    # Verify admin access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next(
        (o for o in user_orgs if str(o["id"]) == workflow["organization_id"]),
        None
    )
    
    if not user_org:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if user_org.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Build update dict
    update_data = updates.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    updated = await db.update_workflow(workflow_id, update_data)
    
    logger.info(
        "workflow_updated",
        workflow_id=str(workflow_id),
        updates=list(update_data.keys())
    )
    
    return WorkflowResponse(**updated)


@router.post(
    "/{workflow_id}/activate",
    response_model=WorkflowResponse,
    summary="Activate Workflow",
    description="Activate a workflow for execution."
)
async def activate_workflow(
    workflow_id: UUID,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> WorkflowResponse:
    """Activate a workflow."""
    workflow = await db.get_workflow(workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    # Verify admin access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next(
        (o for o in user_orgs if str(o["id"]) == workflow["organization_id"]),
        None
    )
    
    if not user_org or user_org.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    updated = await db.update_workflow(workflow_id, {"is_active": True})
    
    logger.info("workflow_activated", workflow_id=str(workflow_id))
    
    return WorkflowResponse(**updated)


@router.post(
    "/{workflow_id}/deactivate",
    response_model=WorkflowResponse,
    summary="Deactivate Workflow",
    description="Deactivate a workflow to prevent execution."
)
async def deactivate_workflow(
    workflow_id: UUID,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> WorkflowResponse:
    """Deactivate a workflow."""
    workflow = await db.get_workflow(workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    # Verify admin access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next(
        (o for o in user_orgs if str(o["id"]) == workflow["organization_id"]),
        None
    )
    
    if not user_org or user_org.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    updated = await db.update_workflow(workflow_id, {"is_active": False})
    
    logger.info("workflow_deactivated", workflow_id=str(workflow_id))
    
    return WorkflowResponse(**updated)
