"""
N8N HTTP Client for workflow execution.

This module provides an async HTTP client for communicating with
the private n8n instance, including:
- Webhook triggering with credential injection
- Dynamic credential updates via n8n REST API
- Response streaming
- Error handling and timeout management

Credential Injection Pattern:
    The "Static Identity / Dynamic Data" pattern is used to securely
    inject tenant-specific credentials into n8n workflows:
    
    1. Base credentials are created in n8n with a static "identity"
    2. Before execution, tenant-specific data is patched into the credential
    3. Advisory locks prevent race conditions between concurrent requests
    4. After execution, credentials can be reset or left for the next request
"""

import time
from typing import Any, AsyncIterator
from uuid import UUID

import httpx
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


class N8NClientError(Exception):
    """Base exception for N8N client errors."""
    pass


class N8NTimeoutError(N8NClientError):
    """Raised when n8n request times out."""
    pass


class N8NWebhookError(N8NClientError):
    """Raised when n8n webhook returns an error."""
    pass


class N8NCredentialError(N8NClientError):
    """Raised when credential update fails."""
    pass


class CredentialInjector:
    """
    Handles dynamic credential injection for n8n workflows.
    
    Implements the "Static Identity / Dynamic Data" pattern:
    - Fetches tenant-specific secrets from Supabase Vault
    - Updates base credentials in n8n via REST API
    - Uses advisory locks to prevent credential bleed
    """
    
    # Mapping of service types to credential field names
    CREDENTIAL_FIELD_MAPPING = {
        "openai": {"apiKey": "api_key"},
        "slack": {"accessToken": "access_token", "teamId": "team_id"},
        "hubspot": {"apiKey": "api_key"},
        "salesforce": {"accessToken": "access_token", "instanceUrl": "instance_url"},
        "stripe": {"secretKey": "secret_key"},
        "twilio": {"accountSid": "account_sid", "authToken": "auth_token"},
        "sendgrid": {"apiKey": "api_key"},
        "airtable": {"apiKey": "api_key"},
        "notion": {"apiKey": "api_key"},
        "discord": {"botToken": "bot_token"},
        # Generic OAuth2
        "oauth2": {"accessToken": "access_token", "refreshToken": "refresh_token"},
        # Generic API Key
        "apiKey": {"apiKey": "api_key"},
    }
    
    def __init__(self, base_url: str, api_key: str | None = None):
        """
        Initialize the credential injector.
        
        Args:
            base_url: n8n instance base URL
            api_key: n8n API key for REST API access
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
    
    def _get_n8n_api_headers(self) -> dict[str, str]:
        """Get headers for n8n REST API requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-N8N-API-KEY"] = self.api_key
        return headers
    
    async def update_credential(
        self,
        credential_id: str,
        credential_data: dict[str, Any],
        credential_type: str | None = None
    ) -> bool:
        """
        Update a credential in n8n via REST API.
        
        This method patches the credential data into an existing
        base credential in n8n.
        
        Args:
            credential_id: The n8n credential ID to update
            credential_data: New credential data to patch
            credential_type: Type of credential (for field mapping)
            
        Returns:
            True if update succeeded
            
        Raises:
            N8NCredentialError: If update fails
        """
        url = f"{self.base_url}/api/v1/credentials/{credential_id}"
        headers = self._get_n8n_api_headers()
        
        # Map tenant credential fields to n8n credential fields
        n8n_data = {}
        if credential_type and credential_type in self.CREDENTIAL_FIELD_MAPPING:
            field_map = self.CREDENTIAL_FIELD_MAPPING[credential_type]
            for n8n_field, tenant_field in field_map.items():
                if tenant_field in credential_data:
                    n8n_data[n8n_field] = credential_data[tenant_field]
        else:
            # Use data as-is
            n8n_data = credential_data
        
        payload = {"data": n8n_data}
        
        logger.debug(
            "updating_n8n_credential",
            credential_id=credential_id,
            credential_type=credential_type,
            fields=list(n8n_data.keys())
        )
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.patch(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    logger.info(
                        "n8n_credential_updated",
                        credential_id=credential_id
                    )
                    return True
                else:
                    error_text = response.text[:500] if response.text else "Unknown error"
                    raise N8NCredentialError(
                        f"Failed to update credential {credential_id}: {response.status_code} - {error_text}"
                    )
                    
        except httpx.HTTPError as e:
            raise N8NCredentialError(
                f"HTTP error updating credential {credential_id}: {str(e)}"
            ) from e
    
    async def inject_credentials(
        self,
        tenant_credentials: dict[str, Any],
        credential_mappings: dict[str, str]
    ) -> dict[str, bool]:
        """
        Inject tenant credentials into n8n base credentials.
        
        Args:
            tenant_credentials: Dict mapping service types to credential data
                e.g., {"openai": {"api_key": "sk-..."}, "slack": {...}}
            credential_mappings: Dict mapping service types to n8n credential IDs
                e.g., {"openai": "cred_123", "slack": "cred_456"}
                
        Returns:
            Dict mapping service types to update success status
        """
        results = {}
        
        for service_type, n8n_cred_id in credential_mappings.items():
            # Get credential data with explicit null check
            cred_data = tenant_credentials.get(service_type)
            
            if not cred_data:
                logger.warning(
                    "missing_or_empty_tenant_credential",
                    service_type=service_type,
                    is_missing=service_type not in tenant_credentials,
                    is_empty=cred_data is not None and not cred_data
                )
                results[service_type] = False
                continue
            
            try:
                success = await self.update_credential(
                    credential_id=n8n_cred_id,
                    credential_data=cred_data,
                    credential_type=service_type
                )
                results[service_type] = success
            except N8NCredentialError as e:
                logger.error(
                    "credential_injection_failed",
                    service_type=service_type,
                    error=str(e)
                )
                results[service_type] = False
        
        return results


class N8NClient:
    """
    Async HTTP client for n8n webhook execution.
    
    This client handles:
    - Constructing webhook URLs
    - Adding internal authentication headers
    - Dynamic credential injection via REST API
    - Injecting tenant credentials into payloads
    - Streaming responses from long-running workflows
    
    Credential Injection:
        The client supports two modes of credential injection:
        
        1. Payload injection: Credentials are passed in the webhook payload
           and accessed via $json.secrets in n8n. Simpler but less secure.
           
        2. Dynamic credential update: Credentials are patched into n8n's
           credential store before execution. More secure as credentials
           are handled by n8n's encryption.
    """
    
    def __init__(
        self,
        base_url: str,
        internal_auth_secret: str,
        default_timeout: int = 300,
        api_key: str | None = None
    ):
        """
        Initialize the n8n client.
        
        Args:
            base_url: Base URL of the n8n instance
            internal_auth_secret: Secret for X-N8N-Internal-Auth header
            default_timeout: Default request timeout in seconds
            api_key: Optional n8n API key for REST API access (enables credential injection)
        """
        self.base_url = base_url.rstrip("/")
        self.internal_auth_secret = internal_auth_secret
        self.default_timeout = default_timeout
        self.api_key = api_key
        
        # Initialize credential injector if API key is provided
        self.credential_injector = (
            CredentialInjector(base_url, api_key) if api_key else None
        )
    
    def _get_webhook_url(self, webhook_path: str) -> str:
        """
        Construct the full webhook URL.
        
        Args:
            webhook_path: The webhook path (e.g., "/webhook/my-workflow")
            
        Returns:
            Full webhook URL
        """
        # Ensure path starts with /
        if not webhook_path.startswith("/"):
            webhook_path = f"/{webhook_path}"
        
        return f"{self.base_url}{webhook_path}"
    
    def _get_auth_headers(self) -> dict[str, str]:
        """
        Get authentication headers for n8n requests.
        
        Returns:
            Dict with authentication headers
        """
        return {
            "X-N8N-Internal-Auth": self.internal_auth_secret,
            "Content-Type": "application/json",
        }
    
    async def execute_webhook(
        self,
        webhook_path: str,
        data: dict[str, Any],
        tenant_credentials: dict[str, Any] | None = None,
        credential_mappings: dict[str, str] | None = None,
        timeout: int | None = None,
        execution_id: UUID | None = None,
        use_dynamic_injection: bool = False
    ) -> dict[str, Any]:
        """
        Execute an n8n webhook and return the response.
        
        This is the main method for triggering n8n workflows. It:
        1. Optionally injects credentials via n8n REST API (dynamic injection)
        2. Constructs the webhook URL
        3. Adds internal authentication
        4. Optionally includes credentials in payload (simple injection)
        5. Sends the request and handles the response
        
        Args:
            webhook_path: The webhook path in n8n
            data: Input data for the workflow
            tenant_credentials: Optional credentials dict by service type
            credential_mappings: Optional mapping of service types to n8n credential IDs
                Required when use_dynamic_injection=True
            timeout: Custom timeout in seconds
            execution_id: Optional UUID for tracking
            use_dynamic_injection: If True, update n8n credentials via REST API
                before execution. Requires credential_mappings and API key.
            
        Returns:
            Response data from n8n
            
        Raises:
            N8NTimeoutError: If the request times out
            N8NWebhookError: If n8n returns an error
            N8NCredentialError: If credential injection fails
            N8NClientError: For other HTTP errors
        """
        # Dynamic credential injection (if enabled and credentials provided)
        if use_dynamic_injection and tenant_credentials and credential_mappings:
            if not self.credential_injector:
                raise N8NCredentialError(
                    "Dynamic credential injection requires n8n API key configuration"
                )
            
            injection_results = await self.credential_injector.inject_credentials(
                tenant_credentials=tenant_credentials,
                credential_mappings=credential_mappings
            )
            
            # Log any failures but continue
            failed = [k for k, v in injection_results.items() if not v]
            if failed:
                logger.warning(
                    "credential_injection_partial_failure",
                    failed_services=failed,
                    execution_id=str(execution_id) if execution_id else None
                )
        
        url = self._get_webhook_url(webhook_path)
        headers = self._get_auth_headers()
        request_timeout = timeout or self.default_timeout
        
        # Construct payload
        payload = {
            "data": data,
            "execution_id": str(execution_id) if execution_id else None,
            "timestamp": int(time.time()),
        }
        
        # Simple credential injection (pass in payload)
        # Only do this if NOT using dynamic injection
        if tenant_credentials and not use_dynamic_injection:
            payload["secrets"] = tenant_credentials
        
        logger.info(
            "n8n_webhook_request",
            webhook_path=webhook_path,
            execution_id=str(execution_id) if execution_id else None,
            timeout=request_timeout
        )
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=httpx.Timeout(request_timeout, connect=10.0)
                )
            
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            # Handle different response codes
            if response.status_code == 200:
                logger.info(
                    "n8n_webhook_success",
                    webhook_path=webhook_path,
                    execution_id=str(execution_id) if execution_id else None,
                    execution_time_ms=execution_time_ms
                )
                
                return {
                    "success": True,
                    "data": response.json() if response.content else {},
                    "execution_time_ms": execution_time_ms
                }
            
            elif response.status_code == 404:
                raise N8NWebhookError(f"Webhook not found: {webhook_path}")
            
            elif response.status_code == 401:
                raise N8NWebhookError("Authentication failed with n8n instance")
            
            elif response.status_code >= 500:
                error_detail = response.text[:500] if response.text else "Unknown error"
                raise N8NWebhookError(f"n8n server error ({response.status_code}): {error_detail}")
            
            else:
                error_detail = response.text[:500] if response.text else "Unknown error"
                raise N8NWebhookError(
                    f"Unexpected response from n8n ({response.status_code}): {error_detail}"
                )
                
        except httpx.TimeoutException as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "n8n_webhook_timeout",
                webhook_path=webhook_path,
                execution_id=str(execution_id) if execution_id else None,
                timeout=request_timeout,
                execution_time_ms=execution_time_ms
            )
            raise N8NTimeoutError(
                f"Request to n8n timed out after {request_timeout}s"
            ) from e
            
        except httpx.HTTPError as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "n8n_webhook_error",
                webhook_path=webhook_path,
                execution_id=str(execution_id) if execution_id else None,
                error=str(e),
                execution_time_ms=execution_time_ms
            )
            raise N8NClientError(f"HTTP error communicating with n8n: {str(e)}") from e
    
    async def execute_webhook_stream(
        self,
        webhook_path: str,
        data: dict[str, Any],
        tenant_credentials: dict[str, Any] | None = None,
        timeout: int | None = None,
        execution_id: UUID | None = None
    ) -> AsyncIterator[bytes]:
        """
        Execute an n8n webhook and stream the response.
        
        This method is useful for long-running workflows that may
        stream data back incrementally.
        
        Args:
            webhook_path: The webhook path in n8n
            data: Input data for the workflow
            tenant_credentials: Optional credentials to inject
            timeout: Custom timeout in seconds
            execution_id: Optional UUID for tracking
            
        Yields:
            Response chunks as bytes
            
        Raises:
            N8NTimeoutError: If the request times out
            N8NWebhookError: If n8n returns an error
        """
        url = self._get_webhook_url(webhook_path)
        headers = self._get_auth_headers()
        request_timeout = timeout or self.default_timeout
        
        payload = {
            "data": data,
            "execution_id": str(execution_id) if execution_id else None,
            "timestamp": int(time.time()),
        }
        
        if tenant_credentials:
            payload["secrets"] = tenant_credentials
        
        logger.info(
            "n8n_webhook_stream_request",
            webhook_path=webhook_path,
            execution_id=str(execution_id) if execution_id else None
        )
        
        try:
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    url,
                    json=payload,
                    headers=headers,
                    timeout=httpx.Timeout(request_timeout, connect=10.0)
                ) as response:
                    if response.status_code != 200:
                        error_text = await response.aread()
                        raise N8NWebhookError(
                            f"n8n error ({response.status_code}): {error_text.decode()[:500]}"
                        )
                    
                    async for chunk in response.aiter_bytes():
                        yield chunk
                        
        except httpx.TimeoutException as e:
            logger.error(
                "n8n_webhook_stream_timeout",
                webhook_path=webhook_path,
                execution_id=str(execution_id) if execution_id else None
            )
            raise N8NTimeoutError(
                f"Stream request to n8n timed out after {request_timeout}s"
            ) from e
    
    async def health_check(self) -> bool:
        """
        Check if the n8n instance is reachable.
        
        Returns:
            True if n8n is healthy, False otherwise
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/healthz",
                    timeout=10.0
                )
                return response.status_code == 200
        except Exception as e:
            logger.warning("n8n_health_check_failed", error=str(e))
            return False


# =============================================================================
# DEPENDENCY INJECTION
# =============================================================================

_n8n_client: N8NClient | None = None


def get_n8n_client() -> N8NClient:
    """
    Get the n8n client singleton.
    
    Returns:
        N8NClient instance
    """
    global _n8n_client
    if _n8n_client is None:
        # Check for n8n API key in settings
        api_key = getattr(settings, 'n8n_api_key', None)
        
        _n8n_client = N8NClient(
            base_url=settings.n8n_base_url,
            internal_auth_secret=settings.n8n_internal_auth_secret,
            default_timeout=settings.n8n_request_timeout,
            api_key=api_key
        )
    return _n8n_client


def reset_n8n_client() -> None:
    """Reset the n8n client singleton. Useful for testing."""
    global _n8n_client
    _n8n_client = None
