"""
Database service for Supabase operations.

This module provides async database operations using supabase-py,
following the principle of least privilege with RLS policies.
"""

from typing import Any
from uuid import UUID
from functools import lru_cache

import structlog
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions

from app.core.config import settings
from app.core.security import api_key_manager
from app.models.schemas import ExecutionStatus

logger = structlog.get_logger(__name__)


class DatabaseService:
    """
    Async database service for Supabase operations.
    
    This service handles all database interactions with proper error handling,
    logging, and respects RLS policies through service role authentication.
    """
    
    def __init__(self, supabase_url: str, supabase_key: str):
        """
        Initialize the database service.
        
        Args:
            supabase_url: Supabase project URL
            supabase_key: Supabase service role key
        """
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self._client: Client | None = None
    
    @property
    def client(self) -> Client:
        """Get or create Supabase client."""
        if self._client is None:
            options = ClientOptions(
                postgrest_client_timeout=30,
                storage_client_timeout=30,
            )
            self._client = create_client(
                self.supabase_url,
                self.supabase_key,
                options=options
            )
        return self._client
    
    # =========================================================================
    # PROFILE OPERATIONS
    # =========================================================================
    
    async def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """
        Get a profile by ID.
        
        Args:
            profile_id: Clerk user ID
            
        Returns:
            Profile data or None if not found
        """
        try:
            response = self.client.table("profiles").select("*").eq("id", profile_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_profile_error", profile_id=profile_id, error=str(e))
            raise
    
    async def create_profile(self, profile_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new profile.
        
        Args:
            profile_data: Profile data to insert
            
        Returns:
            Created profile data
        """
        try:
            response = self.client.table("profiles").insert(profile_data).execute()
            logger.info("profile_created", profile_id=profile_data.get("id"))
            return response.data[0]
        except Exception as e:
            logger.error("create_profile_error", error=str(e))
            raise
    
    async def upsert_profile(self, profile_data: dict[str, Any]) -> dict[str, Any]:
        """
        Upsert a profile (create or update).
        
        Args:
            profile_data: Profile data
            
        Returns:
            Upserted profile data
        """
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
        """
        Create a new organization with generated API credentials.
        
        Args:
            name: Organization name
            owner_id: Clerk user ID of the owner
            tenant_id: Unique tenant identifier
            plan_type: Subscription plan type
            initial_credits: Starting credit balance
            
        Returns:
            Organization data including API key (only returned once)
        """
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
        """
        Deduct credits from an organization atomically.
        
        Args:
            org_id: Organization UUID
            amount: Credits to deduct
            workflow_id: Optional workflow UUID
            profile_id: Optional user profile ID
            metadata: Optional request metadata
            
        Returns:
            Dict with success, remaining_credits, usage_log_id, error_message
        """
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
        """
        Store tenant credentials in Supabase Vault.
        
        Args:
            org_id: Organization UUID
            credentials: Credentials to store (encrypted at rest)
                Format: {"service_type": {"api_key": "...", ...}, ...}
            
        Returns:
            Secret ID or None on failure
        """
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
            logger.error(
                "store_credentials_error",
                org_id=str(org_id),
                error=str(e)
            )
            raise
    
    async def get_tenant_credentials(self, org_id: UUID) -> dict[str, Any] | None:
        """
        Retrieve tenant credentials from Supabase Vault.
        
        Args:
            org_id: Organization UUID
            
        Returns:
            Decrypted credentials dict by service type, or None
            Format: {"openai": {"api_key": "sk-..."}, "slack": {...}, ...}
        """
        try:
            response = self.client.rpc(
                "private.get_tenant_credentials",
                {"p_org_id": str(org_id)}
            ).execute()
            
            return response.data if response.data else None
        except Exception as e:
            logger.error(
                "get_credentials_error",
                org_id=str(org_id),
                error=str(e)
            )
            raise
    
    async def get_credentials_with_lock(
        self,
        org_id: UUID,
        service_types: list[str] | None = None
    ) -> dict[str, Any] | None:
        """
        Retrieve tenant credentials with an advisory lock held.
        
        This method acquires a transaction-level advisory lock to prevent
        credential bleed between concurrent requests for the same tenant.
        The lock is released when the database transaction commits or rolls back.
        
        Args:
            org_id: Organization UUID
            service_types: Optional list of service types to retrieve
                If None, returns all credentials for the tenant
            
        Returns:
            Dict containing:
                - credentials: The decrypted credentials by service type
                - credential_mappings: Mapping of service types to n8n credential IDs
            
        Raises:
            Exception if lock cannot be acquired (timeout)
        """
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
            
            # Parse the response into a structured format
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
    
    # =========================================================================
    # IMPROVED CREDENTIAL OPERATIONS (V2)
    # =========================================================================
    
    async def acquire_credential_operation(
        self,
        org_id: UUID,
        operation_type: str = "injection",
        timeout_seconds: int = 30,
        worker_id: str | None = None
    ) -> str | None:
        """
        Acquire a credential operation lock for the organization.
        
        Uses the improved locking mechanism that provides better visibility
        and cleanup of stale operations.
        
        Args:
            org_id: Organization UUID
            operation_type: Type of operation (e.g., 'injection', 'update')
            timeout_seconds: How long the operation lock is valid
            worker_id: Optional identifier for the worker acquiring the lock
            
        Returns:
            Operation ID string if acquired, None if failed
        """
        try:
            response = self.client.rpc(
                "fn_acquire_credential_operation",
                {
                    "p_org_id": str(org_id),
                    "p_operation_type": operation_type,
                    "p_timeout_seconds": timeout_seconds,
                    "p_worker_id": worker_id
                }
            ).execute()
            
            if response.data:
                logger.info(
                    "credential_operation_acquired",
                    org_id=str(org_id),
                    operation_type=operation_type,
                    operation_id=response.data
                )
                return response.data
            return None
        except Exception as e:
            logger.warning(
                "credential_operation_acquire_failed",
                org_id=str(org_id),
                operation_type=operation_type,
                error=str(e)
            )
            return None
    
    async def release_credential_operation(self, operation_id: str) -> bool:
        """
        Release a credential operation lock.
        
        Args:
            operation_id: The operation ID returned from acquire_credential_operation
            
        Returns:
            True if released successfully, False otherwise
        """
        try:
            response = self.client.rpc(
                "fn_release_credential_operation",
                {"p_operation_id": operation_id}
            ).execute()
            
            logger.debug(
                "credential_operation_released",
                operation_id=operation_id
            )
            return bool(response.data)
        except Exception as e:
            logger.error(
                "credential_operation_release_error",
                operation_id=operation_id,
                error=str(e)
            )
            return False
    
    async def delete_tenant_credentials(self, org_id: UUID) -> bool:
        """Delete tenant credentials from Vault."""
        try:
            response = self.client.rpc(
                "private.delete_tenant_credentials",
                {"p_org_id": str(org_id)}
            ).execute()
            
            return response.data if response.data else False
        except Exception as e:
            logger.error(
                "delete_credentials_error",
                org_id=str(org_id),
                error=str(e)
            )
            raise
    
    # =========================================================================
    # N8N BASE CREDENTIALS OPERATIONS
    # =========================================================================
    
    async def get_n8n_base_credentials(
        self,
        service_types: list[str] | None = None
    ) -> dict[str, str]:
        """
        Get the mapping of service types to n8n base credential IDs.
        
        Args:
            service_types: Optional list of service types to filter
            
        Returns:
            Dict mapping service types to n8n credential IDs
            e.g., {"openai": "cred_123", "slack": "cred_456"}
        """
        try:
            query = self.client.table("n8n_base_credentials").select(
                "service_type, n8n_credential_id"
            ).eq("is_active", True)
            
            if service_types:
                query = query.in_("service_type", service_types)
            
            response = query.execute()
            
            return {
                row["service_type"]: row["n8n_credential_id"]
                for row in response.data
            } if response.data else {}
        except Exception as e:
            logger.error("get_n8n_base_credentials_error", error=str(e))
            raise
    
    async def upsert_n8n_base_credential(
        self,
        service_type: str,
        n8n_credential_id: str,
        description: str | None = None
    ) -> dict[str, Any]:
        """
        Create or update an n8n base credential mapping.
        
        Args:
            service_type: The service type (e.g., 'openai', 'slack')
            n8n_credential_id: The credential ID in n8n
            description: Optional description
            
        Returns:
            The created/updated record
        """
        try:
            data = {
                "service_type": service_type,
                "n8n_credential_id": n8n_credential_id,
                "description": description,
                "is_active": True
            }
            
            response = self.client.table("n8n_base_credentials").upsert(
                data,
                on_conflict="service_type"
            ).execute()
            
            logger.info(
                "n8n_base_credential_upserted",
                service_type=service_type,
                n8n_credential_id=n8n_credential_id
            )
            
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(
                "upsert_n8n_base_credential_error",
                service_type=service_type,
                error=str(e)
            )
            raise


# =============================================================================
# DEPENDENCY INJECTION
# =============================================================================

_db_service: DatabaseService | None = None


def get_db_service() -> DatabaseService:
    """
    Get the database service singleton.
    
    Returns:
        DatabaseService instance
    """
    global _db_service
    if _db_service is None:
        _db_service = DatabaseService(
            supabase_url=settings.supabase_url,
            supabase_key=settings.supabase_service_role_key
        )
    return _db_service
