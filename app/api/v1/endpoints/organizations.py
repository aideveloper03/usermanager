"""
Organization Management Endpoints.

Provides CRUD operations for organizations including:
- Organization creation with API key generation
- Organization settings management
- Credit management
- Member management
"""

from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

from app.middleware.auth_middleware import get_current_user
from app.models.schemas import (
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
    OrganizationWithSecrets,
    UsageLogResponse,
    UsageStats,
    PaginationParams,
    PaginatedResponse,
)
from app.services.database import DatabaseService, get_db_service

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=OrganizationWithSecrets,
    status_code=201,
    summary="Create Organization",
    description="""
    Create a new organization.
    
    This endpoint generates:
    - A unique API key for the organization
    - A client secret for HMAC signing
    
    **Important:** The API key and client secret are only returned once.
    Store them securely as they cannot be retrieved later.
    """
)
async def create_organization(
    org_data: OrganizationCreate,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> OrganizationWithSecrets:
    """Create a new organization."""
    user_id = current_user["user_id"]
    
    # Check if tenant_id is already taken
    existing = await db.get_organization_by_tenant(org_data.tenant_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Tenant ID '{org_data.tenant_id}' is already in use"
        )
    
    # Ensure user profile exists
    profile = await db.get_profile(user_id)
    if not profile:
        # Auto-create profile from JWT claims
        claims = current_user.get("claims", {})
        await db.create_profile({
            "id": user_id,
            "email": claims.get("email", f"{user_id}@unknown.com"),
            "name": claims.get("name"),
        })
    
    # Determine initial credits based on plan
    initial_credits = {
        "free": 100,
        "starter": 1000,
        "professional": 10000,
        "enterprise": 100000,
    }.get(org_data.plan_type, 100)
    
    # Create organization
    org = await db.create_organization(
        name=org_data.name,
        owner_id=user_id,
        tenant_id=org_data.tenant_id,
        plan_type=org_data.plan_type,
        initial_credits=initial_credits
    )
    
    logger.info(
        "organization_created",
        org_id=org["id"],
        tenant_id=org_data.tenant_id,
        owner_id=user_id
    )
    
    return OrganizationWithSecrets(**org)


@router.get(
    "",
    response_model=list[OrganizationResponse],
    summary="List My Organizations",
    description="Get all organizations the current user is a member of."
)
async def list_organizations(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> list[OrganizationResponse]:
    """List organizations for the current user."""
    user_id = current_user["user_id"]
    orgs = await db.get_user_organizations(user_id)
    return [OrganizationResponse(**org) for org in orgs]


@router.get(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Get Organization",
    description="Get organization details by ID."
)
async def get_organization(
    org_id: UUID,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> OrganizationResponse:
    """Get organization by ID."""
    org = await db.get_organization(org_id)
    
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Verify user has access to this organization
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    if not any(str(o["id"]) == str(org_id) for o in user_orgs):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return OrganizationResponse(**org)


@router.patch(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Update Organization",
    description="Update organization settings. Requires admin or owner role."
)
async def update_organization(
    org_id: UUID,
    updates: OrganizationUpdate,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> OrganizationResponse:
    """Update organization settings."""
    # Verify user has admin access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next((o for o in user_orgs if str(o["id"]) == str(org_id)), None)
    
    if not user_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if user_org.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Build update dict
    update_data = updates.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    org = await db.update_organization(org_id, update_data)
    
    return OrganizationResponse(**org)


@router.get(
    "/{org_id}/usage",
    response_model=PaginatedResponse,
    summary="Get Usage Logs",
    description="Get paginated usage logs for an organization."
)
async def get_usage_logs(
    org_id: UUID,
    page: int = 1,
    page_size: int = 20,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> PaginatedResponse:
    """Get usage logs for an organization."""
    # Verify access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    if not any(str(o["id"]) == str(org_id) for o in user_orgs):
        raise HTTPException(status_code=403, detail="Access denied")
    
    pagination = PaginationParams(page=page, page_size=page_size)
    
    logs = await db.get_usage_logs(org_id, limit=pagination.page_size, offset=pagination.offset)
    
    # Get total count (simplified - in production, use a separate count query)
    total = len(logs) + pagination.offset  # Approximate
    
    return PaginatedResponse.create(
        items=[UsageLogResponse(**log) for log in logs],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size
    )


@router.post(
    "/{org_id}/credentials",
    status_code=201,
    summary="Store Tenant Credentials",
    description="""
    Store encrypted credentials for a tenant in Supabase Vault.
    
    These credentials will be injected into n8n workflows when executed.
    Requires owner access.
    """
)
async def store_credentials(
    org_id: UUID,
    credentials: dict[str, Any],
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> dict[str, str]:
    """Store tenant credentials in Vault."""
    # Verify owner access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next((o for o in user_orgs if str(o["id"]) == str(org_id)), None)
    
    if not user_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if user_org.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owner access required")
    
    # Store in Vault
    secret_id = await db.store_tenant_credentials(org_id, credentials)
    
    if not secret_id:
        raise HTTPException(status_code=500, detail="Failed to store credentials")
    
    logger.info(
        "tenant_credentials_stored",
        org_id=str(org_id),
        user_id=current_user["user_id"]
    )
    
    return {"message": "Credentials stored successfully"}


@router.delete(
    "/{org_id}/credentials",
    status_code=204,
    summary="Delete Tenant Credentials",
    description="Delete tenant credentials from Supabase Vault. Requires owner access."
)
async def delete_credentials(
    org_id: UUID,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseService = Depends(get_db_service),
) -> None:
    """Delete tenant credentials from Vault."""
    # Verify owner access
    user_orgs = await db.get_user_organizations(current_user["user_id"])
    user_org = next((o for o in user_orgs if str(o["id"]) == str(org_id)), None)
    
    if not user_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if user_org.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owner access required")
    
    await db.delete_tenant_credentials(org_id)
    
    logger.info(
        "tenant_credentials_deleted",
        org_id=str(org_id),
        user_id=current_user["user_id"]
    )
