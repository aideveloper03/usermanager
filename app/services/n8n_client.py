"""
N8N HTTP Client for workflow execution.

This module provides an async HTTP client for communicating with
the private n8n instance, including:
- Webhook triggering with credential injection
- Response streaming
- Error handling and timeout management
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


class N8NClient:
    """
    Async HTTP client for n8n webhook execution.
    
    This client handles:
    - Constructing webhook URLs
    - Adding internal authentication headers
    - Injecting tenant credentials into payloads
    - Streaming responses from long-running workflows
    """
    
    def __init__(
        self,
        base_url: str,
        internal_auth_secret: str,
        default_timeout: int = 300
    ):
        """
        Initialize the n8n client.
        
        Args:
            base_url: Base URL of the n8n instance
            internal_auth_secret: Secret for X-N8N-Internal-Auth header
            default_timeout: Default request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.internal_auth_secret = internal_auth_secret
        self.default_timeout = default_timeout
    
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
        timeout: int | None = None,
        execution_id: UUID | None = None
    ) -> dict[str, Any]:
        """
        Execute an n8n webhook and return the response.
        
        This is the main method for triggering n8n workflows. It:
        1. Constructs the webhook URL
        2. Adds internal authentication
        3. Injects tenant credentials if provided
        4. Sends the request and handles the response
        
        Args:
            webhook_path: The webhook path in n8n
            data: Input data for the workflow
            tenant_credentials: Optional credentials to inject into payload
            timeout: Custom timeout in seconds
            execution_id: Optional UUID for tracking
            
        Returns:
            Response data from n8n
            
        Raises:
            N8NTimeoutError: If the request times out
            N8NWebhookError: If n8n returns an error
            N8NClientError: For other HTTP errors
        """
        url = self._get_webhook_url(webhook_path)
        headers = self._get_auth_headers()
        request_timeout = timeout or self.default_timeout
        
        # Construct payload with optional credential injection
        payload = {
            "data": data,
            "execution_id": str(execution_id) if execution_id else None,
            "timestamp": int(time.time()),
        }
        
        if tenant_credentials:
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
        _n8n_client = N8NClient(
            base_url=settings.n8n_base_url,
            internal_auth_secret=settings.n8n_internal_auth_secret,
            default_timeout=settings.n8n_request_timeout
        )
    return _n8n_client
