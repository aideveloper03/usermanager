"""
Pytest configuration and fixtures for the N8N Orchestration Gateway tests.
"""

import os
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Set test environment variables before importing app
os.environ.update({
    "ENVIRONMENT": "development",
    "DEBUG": "true",
    "SUPABASE_URL": "https://test.supabase.co",
    "SUPABASE_ANON_KEY": "test-anon-key",
    "SUPABASE_SERVICE_ROLE_KEY": "test-service-role-key",
    "CLERK_SECRET_KEY": "sk_test_xxxxx",
    "CLERK_PUBLISHABLE_KEY": "pk_test_xxxxx",
    "CLERK_JWT_ISSUER": "https://test.clerk.accounts.dev",
    "CLERK_JWKS_URL": "https://test.clerk.accounts.dev/.well-known/jwks.json",
    "N8N_BASE_URL": "http://localhost:5678",
    "N8N_INTERNAL_AUTH_SECRET": "test-internal-secret-that-is-at-least-32-characters-long-for-testing",
    "REDIS_URL": "redis://localhost:6379/0",
    "ENABLE_RATE_LIMITING": "false",
    "ENABLE_HMAC_VALIDATION": "false",
    "ENABLE_FINGERPRINTING": "true",
})

from app.main import app
from app.services.database import DatabaseService
from app.services.n8n_client import N8NClient


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def test_client() -> Generator[TestClient, None, None]:
    """Create a test client for synchronous tests."""
    with TestClient(app) as client:
        yield client


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_db_service() -> Generator[MagicMock, None, None]:
    """Create a mock database service."""
    mock = MagicMock(spec=DatabaseService)
    
    # Configure default return values
    mock.get_profile = AsyncMock(return_value={
        "id": "user_test123",
        "email": "test@example.com",
        "name": "Test User",
    })
    
    mock.get_organization = AsyncMock(return_value={
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "tenant_id": "test-tenant",
        "api_key_hash": "hashed_key",
        "api_key_prefix": "gw_live_test",
        "credits": 1000,
        "plan_type": "professional",
        "is_active": True,
    })
    
    mock.get_organization_by_tenant = AsyncMock(return_value={
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "tenant_id": "test-tenant",
        "credits": 1000,
        "is_active": True,
    })
    
    mock.get_workflow = AsyncMock(return_value={
        "id": "workflow-uuid-12345",
        "organization_id": "org-uuid-12345",
        "name": "Test Workflow",
        "n8n_workflow_id": "n8n-123",
        "n8n_webhook_path": "/webhook/test",
        "is_active": True,
        "credits_per_execution": 1,
        "timeout_seconds": 300,
    })
    
    mock.get_workflow_by_org = AsyncMock(return_value={
        "id": "workflow-uuid-12345",
        "organization_id": "org-uuid-12345",
        "name": "Test Workflow",
        "n8n_workflow_id": "n8n-123",
        "n8n_webhook_path": "/webhook/test",
        "is_active": True,
        "credits_per_execution": 1,
        "timeout_seconds": 300,
    })
    
    mock.deduct_credits = AsyncMock(return_value={
        "success": True,
        "remaining_credits": 999,
        "usage_log_id": "usage-uuid-12345",
        "error_message": None,
    })
    
    mock.update_usage_status = AsyncMock(return_value=True)
    mock.get_tenant_credentials = AsyncMock(return_value={"api_key": "secret"})
    mock.log_security_event = AsyncMock(return_value={})
    
    with patch("app.services.database.get_db_service", return_value=mock):
        yield mock


@pytest.fixture
def mock_n8n_client() -> Generator[MagicMock, None, None]:
    """Create a mock n8n client."""
    mock = MagicMock(spec=N8NClient)
    
    mock.execute_webhook = AsyncMock(return_value={
        "success": True,
        "data": {"result": "workflow executed"},
        "execution_time_ms": 150,
    })
    
    mock.health_check = AsyncMock(return_value=True)
    
    with patch("app.services.n8n_client.get_n8n_client", return_value=mock):
        yield mock


@pytest.fixture
def mock_jwt_verifier() -> Generator[MagicMock, None, None]:
    """Create a mock JWT verifier."""
    mock = MagicMock()
    
    mock.verify_token = AsyncMock(return_value={
        "sub": "user_test123",
        "org_id": "org_test123",
        "email": "test@example.com",
        "iat": 1700000000,
        "exp": 1700003600,
    })
    
    mock.get_user_id_from_claims = MagicMock(return_value="user_test123")
    mock.get_org_id_from_claims = MagicMock(return_value="org_test123")
    
    with patch("app.middleware.auth_middleware.jwt_verifier", mock):
        with patch("app.core.security.jwt_verifier", mock):
            yield mock


@pytest.fixture
def authenticated_headers() -> dict[str, str]:
    """Get headers for an authenticated request."""
    return {
        "Authorization": "Bearer test-jwt-token",
        "X-Tenant-ID": "test-tenant",
    }


@pytest.fixture
def api_key_headers() -> dict[str, str]:
    """Get headers for API key authentication."""
    import time
    return {
        "X-API-Key": "gw_live_test1234567890abcdef",
        "X-Tenant-ID": "test-tenant",
        "X-Timestamp": str(int(time.time())),
        "X-Signature": "test-signature",
    }


# =============================================================================
# TEST DATA
# =============================================================================

@pytest.fixture
def sample_execute_request() -> dict:
    """Sample execute request payload."""
    return {
        "workflow_id": "workflow-uuid-12345",
        "data": {
            "input": "test data",
            "params": {"key": "value"},
        },
        "metadata": {
            "source": "test",
        },
    }


@pytest.fixture
def sample_organization_create() -> dict:
    """Sample organization creation payload."""
    return {
        "name": "New Test Organization",
        "tenant_id": "new-test-tenant",
        "plan_type": "starter",
    }


@pytest.fixture
def sample_workflow_create() -> dict:
    """Sample workflow creation payload."""
    return {
        "name": "New Test Workflow",
        "description": "A workflow for testing",
        "n8n_workflow_id": "n8n-new-123",
        "n8n_webhook_path": "/webhook/new-test",
        "credits_per_execution": 2,
        "timeout_seconds": 120,
    }
