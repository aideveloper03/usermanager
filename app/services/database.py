"""
Database service for Supabase operations with Clerk Native Integration.

This module provides database operations using supabase-py with proper
Row-Level Security (RLS) support through Clerk JWT token authentication.

Architecture:
    - ServiceRoleClient: For admin/background operations (bypasses RLS)
    - AuthenticatedClient: Per-request client with Clerk JWT for RLS enforcement

The Clerk JWT is passed to Supabase which validates it against Clerk's JWKS.
RLS policies use auth.jwt()->>'sub' to extract the Clerk user ID.

Setup Requirements:
    1. Configure Clerk as a third-party auth provider in Supabase Dashboard
    2. Add Clerk's JWKS URL to Supabase auth configuration
    3. RLS policies should use auth.jwt()->>'sub' for user identification
"""

from typing import Any
from uuid import UUID
from contextlib import contextmanager
from functools import lru_cache

import structlog
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions

from app.core.config import settings
from app.core.security import api_key_manager
from app.models.schemas import ExecutionStatus

logger = structlog.get_logger(__name__)


# =============================================================================
# SUPABASE CLIENT FACTORY
# =============================================================================


class SupabaseClientFactory:
    """
    Factory for creating Supabase clients with different auth contexts.
    
    Supports two modes:
    1. Service Role: Full admin access, bypasses RLS
    2. Authenticated: Per-request client with Clerk JWT for RLS enforcement
    
    The Clerk JWT is passed in the Authorization header. Supabase validates
    the JWT against Clerk's JWKS and extracts claims for RLS policies.
    """
    
    def __init__(self, supabase_url: str, anon_key: str, service_role_key: str):
        """
        Initialize the client factory.
        
        Args:
            supabase_url: Supabase project URL
            anon_key: Supabase anon/public key (used with JWT for RLS)
            service_role_key: Supabase service role key (admin access)
        """
        self.supabase_url = supabase_url
        self.anon_key = anon_key
        self.service_role_key = service_role_key
        self._service_client: Client | None = None
    
    def get_service_client(self) -> Client:
        """
        Get a Supabase client with service role privileges.
        
        This client bypasses RLS and has full database access.
        Use for admin operations, webhooks, and background jobs.
        
        Returns:
            Supabase Client with service role key
        """
        if self._service_client is None:
            options = ClientOptions(
                postgrest_client_timeout=30,
                storage_client_timeout=20,
            )
            self._service_client = create_client(
                self.supabase_url,
                self.service_role_key,
                options=options
            )
            logger.debug("service_role_client_created")
        return self._service_client
    
    def get_authenticated_client(self, clerk_jwt: str) -> Client:
        """
        Create a Supabase client authenticated with a Clerk JWT.
        
        This client respects RLS policies. The JWT is validated by Supabase
        against Clerk's JWKS, and auth.jwt() claims are available in RLS.
        
        IMPORTANT: This creates a new client per request. The Clerk JWT is
        passed via custom headers that Supabase's PostgREST understands.
        
        Args:
            clerk_jwt: The Clerk session token (JWT)
            
        Returns:
            Supabase Client with user authentication
        """
        # Create a new client with the anon key as the apikey
        # The Clerk JWT is passed as the Authorization bearer token via headers
        options = ClientOptions(
            postgrest_client_timeout=30,
            storage_client_timeout=20,
            headers={
                "Authorization": f"Bearer {clerk_jwt}",
            }
        )
        
        client = create_client(
            self.supabase_url,
            self.anon_key,  # Use anon key - RLS will be enforced
            options=options
        )
        
        logger.debug("authenticated_client_created")
        return client


# Global factory instance
_client_factory: SupabaseClientFactory | None = None


def get_client_factory() -> SupabaseClientFactory:
    """Get the Supabase client factory singleton."""
    global _client_factory
    if _client_factory is None:
        _client_factory = SupabaseClientFactory(
            supabase_url=settings.supabase_url,
            anon_key=settings.supabase_anon_key,
            service_role_key=settings.supabase_service_role_key
        )
    return _client_factory


# =============================================================================
# DATABASE SERVICE BASE CLASS
# =============================================================================


class DatabaseService:
    """
    Database service for Supabase operations.
    
    This is the base class providing database operations.
    It can be initialized with either a service role client
    or an authenticated client with Clerk JWT.
    
    For RLS-protected operations, use AuthenticatedDatabaseService.
    For admin operations, use get_db_service() which returns a service role client.
    """
    
    def __init__(self, client: Client, user_id: str | None = None):
        """
        Initialize the database service.
        
        Args:
            client: Supabase client instance
            user_id: Optional Clerk user ID (for logging/context)
        """
        self._client = client
        self._user_id = user_id
    
    @property
    def client(self) -> Client:
        """Get the Supabase client."""
        return self._client
    
    @property
    def user_id(self) -> str | None:
        """Get the authenticated user ID (if available)."""
        return self._user_id
    
    # =========================================================================
    # PROFILE OPERATIONS
    # =========================================================================
    
    async def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """Get a profile by ID (Clerk user ID)."""
        try:
            response = self.client.table("profiles").select("*").eq("id", profile_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_profile_error", profile_id=profile_id, error=str(e))
            raise
    
    async def create_profile(self, profile_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new profile."""
        try:
            response = self.client.table("profiles").insert(profile_data).execute()
            logger.info("profile_created", profile_id=profile_data.get("id"))
            return response.data[0]
        except Exception as e:
            logger.error("create_profile_error", error=str(e))
            raise
    
    async def upsert_profile(self, profile_data: dict[str, Any]) -> dict[str, Any]:
        """Upsert a profile (create or update)."""
        try:
            response = self.client.table("profiles").upsert(
                profile_data,
                on_conflict="id"
            ).execute()
            logger.info("profile_upserted", profile_id=profile_data.get("id"))
            return response.data[0]
        except Exception as e:
            logger.error("upsert_profile_error", error=str(e))
            raise
    
    # =========================================================================
    # ORGANIZATION OPERATIONS
    # =========================================================================
    
    async def get_organization(self, org_id: UUID) -> dict[str, Any] | None:
        """Get an organization by ID."""
        try:
            response = self.client.table("organizations").select("*").eq(
                "id", str(org_id)
            ).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_organization_error", org_id=str(org_id), error=str(e))
            raise
    
    async def get_organization_by_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        """Get an organization by tenant ID."""
        try:
            response = self.client.table("organizations").select("*").eq(
                "tenant_id", tenant_id
            ).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_org_by_tenant_error", tenant_id=tenant_id, error=str(e))
            raise
    
    async def get_organization_by_api_key_prefix(
        self, 
        key_prefix: str
    ) -> dict[str, Any] | None:
        """Get an organization by API key prefix."""
        try:
            response = self.client.table("organizations").select("*").eq(
                "api_key_prefix", key_prefix
            ).eq("is_active", True).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_org_by_key_error", key_prefix=key_prefix, error=str(e))
            raise
    
    async def create_organization(
        self,
        name: str,
        owner_id: str,
        tenant_id: str,
        plan_type: str = "free",
        initial_credits: int = 100
    ) -> dict[str, Any]:
        """Create a new organization with generated API credentials."""
        # Generate API key and client secret
        api_key, key_prefix, key_hash = api_key_manager.generate_api_key()
        client_secret, secret_hash = api_key_manager.generate_client_secret()
        
        org_data = {
            "name": name,
            "owner_id": owner_id,
            "tenant_id": tenant_id,
            "api_key_hash": key_hash,
            "api_key_prefix": key_prefix,
            "client_secret_hash": secret_hash,
            "credits": initial_credits,
            "plan_type": plan_type,
            "is_active": True,
        }
        
        try:
            response = self.client.table("organizations").insert(org_data).execute()
            org = response.data[0]
            
            # Add the raw credentials (only returned on creation)
            org["api_key"] = api_key
            org["client_secret"] = client_secret
            
            logger.info(
                "organization_created",
                org_id=org["id"],
                tenant_id=tenant_id,
                owner_id=owner_id
            )
            
            return org
        except Exception as e:
            logger.error("create_organization_error", error=str(e))
            raise
    
    async def update_organization(
        self,
        org_id: UUID,
        updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an organization."""
        try:
            response = self.client.table("organizations").update(updates).eq(
                "id", str(org_id)
            ).execute()
            return response.data[0]
        except Exception as e:
            logger.error("update_organization_error", org_id=str(org_id), error=str(e))
            raise
    
    async def get_user_organizations(self, profile_id: str) -> list[dict[str, Any]]:
        """Get all organizations a user is a member of."""
        try:
            response = self.client.table("organization_members").select(
                "organization_id, role, organizations(*)"
            ).eq("profile_id", profile_id).execute()
            
            return [
                {**item["organizations"], "role": item["role"]}
                for item in response.data
            ]
        except Exception as e:
            logger.error("get_user_orgs_error", profile_id=profile_id, error=str(e))
            raise
    
    # =========================================================================
    # WORKFLOW OPERATIONS
    # =========================================================================
    
    async def get_workflow(self, workflow_id: UUID) -> dict[str, Any] | None:
        """Get a workflow by ID."""
        try:
            response = self.client.table("workflows").select("*").eq(
                "id", str(workflow_id)
            ).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_workflow_error", workflow_id=str(workflow_id), error=str(e))
            raise
    
    async def get_workflow_by_org(
        self,
        org_id: UUID,
        workflow_id: UUID
    ) -> dict[str, Any] | None:
        """Get a workflow ensuring it belongs to the specified organization."""
        try:
            response = self.client.table("workflows").select("*").eq(
                "id", str(workflow_id)
            ).eq("organization_id", str(org_id)).eq("is_active", True).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(
                "get_workflow_by_org_error",
                workflow_id=str(workflow_id),
                org_id=str(org_id),
                error=str(e)
            )
            raise
    
    async def get_organization_workflows(
        self,
        org_id: UUID,
        active_only: bool = True
    ) -> list[dict[str, Any]]:
        """Get all workflows for an organization."""
        try:
            query = self.client.table("workflows").select("*").eq(
                "organization_id", str(org_id)
            )
            if active_only:
                query = query.eq("is_active", True)
            
            response = query.order("created_at", desc=True).execute()
            return response.data
        except Exception as e:
            logger.error("get_org_workflows_error", org_id=str(org_id), error=str(e))
            raise
    
    async def create_workflow(self, workflow_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new workflow."""
        try:
            response = self.client.table("workflows").insert(workflow_data).execute()
            logger.info(
                "workflow_created",
                workflow_id=response.data[0]["id"],
                org_id=workflow_data.get("organization_id")
            )
            return response.data[0]
        except Exception as e:
            logger.error("create_workflow_error", error=str(e))
            raise
    
    async def update_workflow(
        self,
        workflow_id: UUID,
        updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a workflow."""
        try:
            response = self.client.table("workflows").update(updates).eq(
                "id", str(workflow_id)
            ).execute()
            return response.data[0]
        except Exception as e:
            logger.error("update_workflow_error", workflow_id=str(workflow_id), error=str(e))
            raise
    
    # =========================================================================
    # CREDIT OPERATIONS (RPC)
    # =========================================================================
    
    async def deduct_credits(
        self,
        org_id: UUID,
        amount: int,
        workflow_id: UUID | None = None,
        profile_id: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Deduct credits from an organization atomically."""
        try:
            response = self.client.rpc(
                "fn_deduct_credits",
                {
                    "p_org_id": str(org_id),
                    "p_amount": amount,
                    "p_workflow_id": str(workflow_id) if workflow_id else None,
                    "p_profile_id": profile_id,
                    "p_metadata": metadata or {}
                }
            ).execute()
            
            result = response.data[0] if response.data else {}
            
            if result.get("success"):
                logger.info(
                    "credits_deducted",
                    org_id=str(org_id),
                    amount=amount,
                    remaining=result.get("remaining_credits"),
                    usage_log_id=result.get("usage_log_id")
                )
            else:
                logger.warning(
                    "credit_deduction_failed",
                    org_id=str(org_id),
                    amount=amount,
                    error=result.get("error_message")
                )
            
            return result
        except Exception as e:
            logger.error("deduct_credits_error", org_id=str(org_id), error=str(e))
            raise
    
    async def add_credits(
        self,
        org_id: UUID,
        amount: int,
        invoice_id: UUID | None = None
    ) -> dict[str, Any]:
        """Add credits to an organization."""
        try:
            response = self.client.rpc(
                "fn_add_credits",
                {
                    "p_org_id": str(org_id),
                    "p_amount": amount,
                    "p_invoice_id": str(invoice_id) if invoice_id else None
                }
            ).execute()
            
            result = response.data[0] if response.data else {}
            
            if result.get("success"):
                logger.info(
                    "credits_added",
                    org_id=str(org_id),
                    amount=amount,
                    new_balance=result.get("new_balance")
                )
            
            return result
        except Exception as e:
            logger.error("add_credits_error", org_id=str(org_id), error=str(e))
            raise
    
    async def refund_credits(self, usage_log_id: UUID) -> dict[str, Any]:
        """Refund credits for a failed execution."""
        try:
            response = self.client.rpc(
                "fn_refund_credits",
                {"p_usage_id": str(usage_log_id)}
            ).execute()
            
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error("refund_credits_error", usage_log_id=str(usage_log_id), error=str(e))
            raise
    
    # =========================================================================
    # USAGE LOG OPERATIONS
    # =========================================================================
    
    async def update_usage_status(
        self,
        usage_log_id: UUID,
        status: ExecutionStatus,
        execution_time_ms: int | None = None,
        error_message: str | None = None,
        response_metadata: dict[str, Any] | None = None
    ) -> bool:
        """Update a usage log entry status."""
        try:
            response = self.client.rpc(
                "fn_update_usage_status",
                {
                    "p_usage_id": str(usage_log_id),
                    "p_status": status.value,
                    "p_execution_time_ms": execution_time_ms,
                    "p_error_message": error_message,
                    "p_response_metadata": response_metadata
                }
            ).execute()
            
            return response.data if response.data else False
        except Exception as e:
            logger.error(
                "update_usage_status_error",
                usage_log_id=str(usage_log_id),
                error=str(e)
            )
            raise
    
    async def get_usage_logs(
        self,
        org_id: UUID,
        limit: int = 50,
        offset: int = 0
    ) -> list[dict[str, Any]]:
        """Get usage logs for an organization."""
        try:
            response = self.client.table("usage_logs").select("*").eq(
                "organization_id", str(org_id)
            ).order("created_at", desc=True).range(offset, offset + limit - 1).execute()
            
            return response.data
        except Exception as e:
            logger.error("get_usage_logs_error", org_id=str(org_id), error=str(e))
            raise
    
    # =========================================================================
    # SECURITY LOG OPERATIONS
    # =========================================================================
    
    async def log_security_event(
        self,
        event_type: str,
        severity: str = "info",
        org_id: UUID | None = None,
        profile_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        fingerprint_hash: str | None = None,
        request_path: str | None = None,
        request_method: str | None = None,
        details: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Log a security event to the database."""
        try:
            data = {
                "event_type": event_type,
                "severity": severity,
                "organization_id": str(org_id) if org_id else None,
                "profile_id": profile_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "fingerprint_hash": fingerprint_hash,
                "request_path": request_path,
                "request_method": request_method,
                "details": details or {}
            }
            
            response = self.client.table("security_logs").insert(data).execute()
            return response.data[0]
        except Exception as e:
            logger.error("log_security_event_error", error=str(e))
            # Don't raise - security logging should not break the request
            return {}
    
    # =========================================================================
    # VAULT OPERATIONS
    # =========================================================================
    
    async def store_tenant_credentials(
        self,
        org_id: UUID,
        credentials: dict[str, Any]
    ) -> str | None:
        """Store tenant credentials in Supabase Vault."""
        try:
            response = self.client.rpc(
                "private.store_tenant_credentials",
                {
                    "p_org_id": str(org_id),
                    "p_credentials": credentials
                }
            ).execute()
            
            logger.info(
                "credentials_stored",
                org_id=str(org_id),
                services=list(credentials.keys()) if credentials else []
            )
            
            return response.data if response.data else None
        except Exception as e:
            logger.error("store_credentials_error", org_id=str(org_id), error=str(e))
            raise
    
    async def get_tenant_credentials(self, org_id: UUID) -> dict[str, Any] | None:
        """Retrieve tenant credentials from Supabase Vault."""
        try:
            response = self.client.rpc(
                "private.get_tenant_credentials",
                {"p_org_id": str(org_id)}
            ).execute()
            
            return response.data if response.data else None
        except Exception as e:
            logger.error("get_credentials_error", org_id=str(org_id), error=str(e))
            raise
    
    async def get_credentials_with_lock(
        self,
        org_id: UUID,
        service_types: list[str] | None = None
    ) -> dict[str, Any] | None:
        """Retrieve tenant credentials with an advisory lock held."""
        try:
            response = self.client.rpc(
                "fn_get_credentials_with_lock",
                {
                    "p_org_id": str(org_id),
                    "p_service_types": service_types
                }
            ).execute()
            
            if not response.data:
                return None
            
            credentials = {}
            mappings = {}
            
            for row in response.data:
                service_type = row.get("service_type")
                if service_type:
                    if row.get("credentials"):
                        credentials[service_type] = row["credentials"]
                    if row.get("n8n_credential_id"):
                        mappings[service_type] = row["n8n_credential_id"]
            
            return {
                "credentials": credentials,
                "credential_mappings": mappings
            }
        except Exception as e:
            logger.error(
                "get_credentials_with_lock_error",
                org_id=str(org_id),
                error=str(e)
            )
            raise
    
    async def delete_tenant_credentials(self, org_id: UUID) -> bool:
        """Delete tenant credentials from Vault."""
        try:
            response = self.client.rpc(
                "private.delete_tenant_credentials",
                {"p_org_id": str(org_id)}
            ).execute()
            
            return response.data if response.data else False
        except Exception as e:
            logger.error("delete_credentials_error", org_id=str(org_id), error=str(e))
            raise


# =============================================================================
# AUTHENTICATED DATABASE SERVICE
# =============================================================================


class AuthenticatedDatabaseService(DatabaseService):
    """
    Database service with Clerk JWT authentication for RLS enforcement.
    
    This service should be used for user-scoped operations where RLS
    policies need to be enforced based on the authenticated user.
    
    The Clerk JWT is passed to Supabase, which validates it and makes
    the claims available in RLS policies via auth.jwt().
    
    Example RLS policy:
        CREATE POLICY "users_own_data" ON profiles
            FOR SELECT USING (id = (auth.jwt()->>'sub'));
    """
    
    def __init__(self, clerk_jwt: str, user_id: str):
        """
        Initialize authenticated database service.
        
        Args:
            clerk_jwt: The Clerk session JWT token
            user_id: The Clerk user ID (extracted from JWT 'sub' claim)
        """
        factory = get_client_factory()
        client = factory.get_authenticated_client(clerk_jwt)
        super().__init__(client, user_id)
        self._clerk_jwt = clerk_jwt
        
        logger.debug(
            "authenticated_db_service_created",
            user_id=user_id
        )
    
    @property
    def clerk_jwt(self) -> str:
        """Get the Clerk JWT token."""
        return self._clerk_jwt


# =============================================================================
# DEPENDENCY INJECTION
# =============================================================================

_db_service: DatabaseService | None = None


def get_db_service() -> DatabaseService:
    """
    Get the database service singleton with SERVICE ROLE privileges.
    
    This client bypasses RLS and should only be used for:
    - Webhook handlers
    - Background jobs
    - Admin operations
    - API key authentication (where no user JWT is available)
    
    For user-scoped operations, use get_authenticated_db_service() instead.
    """
    global _db_service
    if _db_service is None:
        factory = get_client_factory()
        _db_service = DatabaseService(factory.get_service_client())
    return _db_service


def get_authenticated_db_service(clerk_jwt: str, user_id: str) -> AuthenticatedDatabaseService:
    """
    Create an authenticated database service for a specific request.
    
    This creates a new Supabase client with the Clerk JWT, enabling
    RLS policies to enforce data access based on the authenticated user.
    
    Args:
        clerk_jwt: The Clerk session JWT token from the request
        user_id: The Clerk user ID (sub claim from JWT)
    
    Returns:
        AuthenticatedDatabaseService with user context for RLS
    
    Example usage in FastAPI:
        @router.get("/my-profile")
        async def get_my_profile(request: Request):
            jwt = getattr(request.state, "clerk_jwt", None)
            user_id = getattr(request.state, "user_id", None)
            if jwt and user_id:
                db = get_authenticated_db_service(jwt, user_id)
                return await db.get_profile(user_id)
    """
    return AuthenticatedDatabaseService(clerk_jwt, user_id)


def reset_db_service() -> None:
    """Reset the database service singleton. Useful for testing."""
    global _db_service, _client_factory
    _db_service = None
    _client_factory = None
