"""
Pytest configuration and fixtures for the N8N Orchestration Gateway tests.

This module provides:
- Test environment configuration
- Mock fixtures for database, n8n client, and JWT verification
- Developer bypass mode for testing without valid tokens
- Sample data fixtures for common test scenarios
"""

import os
import time
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

# =============================================================================
# ENVIRONMENT SETUP
# =============================================================================
# Set test environment variables BEFORE importing the app
# This ensures settings are loaded with test values

os.environ.update({
    # Application settings
    "ENVIRONMENT": "development",
    "DEBUG": "true",
    "APP_NAME": "N8N Gateway Test",
    "APP_VERSION": "1.0.0-test",
    
    # Supabase (mock values)
    "SUPABASE_URL": "https://test.supabase.co",
    "SUPABASE_ANON_KEY": "test-anon-key-12345",
    "SUPABASE_SERVICE_ROLE_KEY": "test-service-role-key-12345",
    
    # Clerk (mock values)
    "CLERK_SECRET_KEY": "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "CLERK_PUBLISHABLE_KEY": "pk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "CLERK_JWT_ISSUER": "https://test.clerk.accounts.dev",
    "CLERK_JWKS_URL": "https://test.clerk.accounts.dev/.well-known/jwks.json",
    
    # N8N (mock values)
    "N8N_BASE_URL": "http://localhost:5678",
    "N8N_INTERNAL_AUTH_SECRET": "test-internal-secret-that-is-at-least-32-characters-long-for-testing",
    "N8N_REQUEST_TIMEOUT": "60",
    "N8N_API_KEY": "test-n8n-api-key",
    "N8N_USE_DYNAMIC_CREDENTIALS": "false",
    
    # Redis (mock values)
    "REDIS_URL": "redis://localhost:6379/0",
    
    # Security settings (disable for testing)
    "ENABLE_RATE_LIMITING": "false",
    "ENABLE_HMAC_VALIDATION": "false",
    "ENABLE_FINGERPRINTING": "true",
    "ENABLE_REQUEST_LOGGING": "false",
    
    # Developer bypass mode (enables testing without JWT)
    "DEV_SKIP_AUTH": "true",
    "DEV_DEFAULT_USER_ID": "test_user_123",
    "DEV_DEFAULT_ORG_ID": "test_org_123",
    
    # CORS (empty for tests)
    "CORS_ORIGINS": "",
})

# Now import the app after environment is set
from app.main import app
from app.services.database import DatabaseService
from app.services.n8n_client import N8NClient, reset_n8n_client
from app.middleware.auth_middleware import DevBypassAuth


# =============================================================================
# TEST CLIENT FIXTURES
# =============================================================================

@pytest.fixture
def test_client() -> Generator[TestClient, None, None]:
    """
    Create a synchronous test client for FastAPI.
    
    Usage:
        def test_health(test_client):
            response = test_client.get("/api/v1/health")
            assert response.status_code == 200
    """
    with TestClient(app) as client:
        yield client


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """
    Create an async test client for FastAPI.
    
    Usage:
        async def test_health(async_client):
            response = await async_client.get("/api/v1/health")
            assert response.status_code == 200
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# =============================================================================
# DATABASE MOCK FIXTURES
# =============================================================================

@pytest.fixture
def mock_db_service() -> Generator[MagicMock, None, None]:
    """
    Create a fully mocked database service.
    
    This mock is pre-configured with common return values for all database
    operations. Individual tests can override specific behaviors.
    
    Usage:
        def test_execute(test_client, mock_db_service):
            # Override specific behavior
            mock_db_service.get_workflow_by_org.return_value = None
            
            response = test_client.post("/api/v1/execute", json=...)
            assert response.status_code == 404
    """
    mock = MagicMock(spec=DatabaseService)
    
    # Profile operations
    mock.get_profile = AsyncMock(return_value={
        "id": "test_user_123",
        "email": "test@example.com",
        "name": "Test User",
        "username": "testuser",
        "email_verified": True,
        "created_at": "2024-01-01T00:00:00Z",
    })
    mock.create_profile = AsyncMock(return_value={
        "id": "test_user_123",
        "email": "test@example.com",
        "name": "Test User",
    })
    mock.upsert_profile = AsyncMock(return_value={
        "id": "test_user_123",
        "email": "test@example.com",
    })
    
    # Organization operations
    mock.get_organization = AsyncMock(return_value={
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "tenant_id": "test-tenant",
        "owner_id": "test_user_123",
        "api_key_hash": "hashed_key_value",
        "api_key_prefix": "gw_live_test",
        "client_secret_hash": "hashed_secret",
        "credits": 1000,
        "plan_type": "professional",
        "is_active": True,
        "settings": {},
        "created_at": "2024-01-01T00:00:00Z",
    })
    mock.get_organization_by_tenant = AsyncMock(return_value={
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "tenant_id": "test-tenant",
        "credits": 1000,
        "is_active": True,
    })
    mock.get_organization_by_api_key_prefix = AsyncMock(return_value={
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "api_key_hash": "hashed_key_value",
        "is_active": True,
    })
    mock.create_organization = AsyncMock(return_value={
        "id": "org-uuid-new",
        "name": "New Organization",
        "api_key": "gw_live_newkey123",
        "client_secret": "secret_123",
    })
    mock.get_user_organizations = AsyncMock(return_value=[{
        "id": "org-uuid-12345",
        "name": "Test Organization",
        "role": "owner",
    }])
    
    # Workflow operations
    mock.get_workflow = AsyncMock(return_value={
        "id": "workflow-uuid-12345",
        "organization_id": "org-uuid-12345",
        "name": "Test Workflow",
        "description": "A test workflow",
        "n8n_workflow_id": "n8n-123",
        "n8n_webhook_path": "/webhook/test-workflow",
        "is_active": True,
        "credits_per_execution": 1,
        "timeout_seconds": 300,
        "settings": {},
    })
    mock.get_workflow_by_org = AsyncMock(return_value={
        "id": "workflow-uuid-12345",
        "organization_id": "org-uuid-12345",
        "name": "Test Workflow",
        "n8n_workflow_id": "n8n-123",
        "n8n_webhook_path": "/webhook/test-workflow",
        "is_active": True,
        "credits_per_execution": 1,
        "timeout_seconds": 300,
    })
    mock.get_organization_workflows = AsyncMock(return_value=[{
        "id": "workflow-uuid-12345",
        "name": "Test Workflow",
        "is_active": True,
    }])
    mock.create_workflow = AsyncMock(return_value={
        "id": "workflow-uuid-new",
        "name": "New Workflow",
    })
    
    # Credit operations
    mock.deduct_credits = AsyncMock(return_value={
        "success": True,
        "remaining_credits": 999,
        "usage_log_id": str(uuid4()),
        "error_message": None,
    })
    mock.add_credits = AsyncMock(return_value={
        "success": True,
        "new_balance": 1100,
        "error_message": None,
    })
    mock.refund_credits = AsyncMock(return_value={
        "success": True,
        "refunded_amount": 1,
        "error_message": None,
    })
    
    # Usage log operations
    mock.update_usage_status = AsyncMock(return_value=True)
    mock.get_usage_logs = AsyncMock(return_value=[])
    
    # Security operations
    mock.log_security_event = AsyncMock(return_value={"id": str(uuid4())})
    
    # Vault/credential operations
    mock.get_tenant_credentials = AsyncMock(return_value={
        "openai": {"api_key": "sk-test-key"},
        "slack": {"access_token": "xoxb-test-token"},
    })
    mock.get_credentials_with_lock = AsyncMock(return_value={
        "credentials": {
            "openai": {"api_key": "sk-test-key"},
        },
        "credential_mappings": {
            "openai": "cred_123",
        },
    })
    mock.store_tenant_credentials = AsyncMock(return_value=str(uuid4()))
    mock.delete_tenant_credentials = AsyncMock(return_value=True)
    mock.get_n8n_base_credentials = AsyncMock(return_value={
        "openai": "cred_123",
        "slack": "cred_456",
    })
    
    # Apply the mock
    with patch("app.services.database.get_db_service", return_value=mock):
        with patch("app.api.v1.endpoints.execute.get_db_service", return_value=mock):
            with patch("app.api.v1.endpoints.workflows.get_db_service", return_value=mock):
                with patch("app.api.v1.endpoints.organizations.get_db_service", return_value=mock):
                    yield mock


@pytest.fixture
def mock_n8n_client() -> Generator[MagicMock, None, None]:
    """
    Create a mocked n8n client.
    
    Pre-configured with successful webhook execution response.
    """
    mock = MagicMock(spec=N8NClient)
    
    mock.execute_webhook = AsyncMock(return_value={
        "success": True,
        "data": {"result": "workflow executed successfully", "output": {}},
        "execution_time_ms": 150,
    })
    mock.execute_webhook_stream = AsyncMock(return_value=iter([b'{"status": "ok"}']))
    mock.health_check = AsyncMock(return_value=True)
    
    # Reset the singleton before applying mock
    reset_n8n_client()
    
    with patch("app.services.n8n_client.get_n8n_client", return_value=mock):
        with patch("app.api.v1.endpoints.execute.get_n8n_client", return_value=mock):
            yield mock
    
    # Reset again after test
    reset_n8n_client()


@pytest.fixture
def mock_jwt_verifier() -> Generator[MagicMock, None, None]:
    """
    Create a mocked JWT verifier for testing JWT authentication.
    
    Note: When DEV_SKIP_AUTH is enabled, this mock won't be used as the
    middleware bypasses JWT verification entirely.
    """
    mock = MagicMock()
    
    mock.verify_token = AsyncMock(return_value={
        "sub": "test_user_123",
        "org_id": "test_org_123",
        "org_role": "admin",
        "email": "test@example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    })
    mock.get_user_id_from_claims = MagicMock(return_value="test_user_123")
    mock.get_org_id_from_claims = MagicMock(return_value="test_org_123")
    mock.get_jwks = AsyncMock(return_value={"keys": []})
    
    with patch("app.middleware.auth_middleware.jwt_verifier", mock):
        with patch("app.core.security.jwt_verifier", mock):
            yield mock


# =============================================================================
# AUTHENTICATION HEADER FIXTURES
# =============================================================================

@pytest.fixture
def dev_bypass_headers() -> dict[str, str]:
    """
    Get headers for developer bypass authentication.
    
    When DEV_SKIP_AUTH=true, these headers set the mock user/org context.
    """
    return {
        "X-Dev-User-ID": "test_user_123",
        "X-Dev-Org-ID": "test_org_123",
        "X-Dev-Role": "admin",
        "X-Tenant-ID": "test-tenant",
    }


@pytest.fixture
def authenticated_headers() -> dict[str, str]:
    """
    Get headers for JWT-authenticated requests.
    
    Note: When DEV_SKIP_AUTH is enabled, JWT validation is bypassed
    but the header is still accepted.
    """
    return {
        "Authorization": "Bearer test-jwt-token-12345",
        "X-Tenant-ID": "test-tenant",
    }


@pytest.fixture
def api_key_headers() -> dict[str, str]:
    """
    Get headers for API key authentication.
    
    Includes HMAC signature headers (X-Signature, X-Timestamp).
    """
    return {
        "X-API-Key": "gw_live_test1234567890abcdefghij",
        "X-Tenant-ID": "test-tenant",
        "X-Timestamp": str(int(time.time())),
        "X-Signature": "test-hmac-signature-12345",
    }


# =============================================================================
# SAMPLE DATA FIXTURES
# =============================================================================

@pytest.fixture
def sample_execute_request() -> dict:
    """Sample execute workflow request payload."""
    return {
        "workflow_id": "workflow-uuid-12345",
        "data": {
            "input": "test input data",
            "parameters": {
                "key1": "value1",
                "key2": 123,
            },
        },
        "metadata": {
            "source": "test-suite",
            "version": "1.0.0",
        },
    }


@pytest.fixture
def sample_organization_create() -> dict:
    """Sample organization creation payload."""
    return {
        "name": "New Test Organization",
        "tenant_id": f"tenant-{uuid4().hex[:8]}",
        "plan_type": "starter",
    }


@pytest.fixture
def sample_workflow_create() -> dict:
    """Sample workflow creation payload."""
    return {
        "name": "New Test Workflow",
        "description": "A workflow created for testing",
        "n8n_workflow_id": f"n8n-{uuid4().hex[:8]}",
        "n8n_webhook_path": f"/webhook/test-{uuid4().hex[:8]}",
        "credits_per_execution": 2,
        "timeout_seconds": 120,
    }


@pytest.fixture
def sample_credentials() -> dict:
    """Sample tenant credentials."""
    return {
        "openai": {
            "api_key": "sk-test-openai-key-12345",
        },
        "slack": {
            "access_token": "xoxb-test-slack-token",
            "team_id": "T12345678",
        },
        "stripe": {
            "secret_key": "sk_test_stripe_key_12345",
        },
    }


@pytest.fixture
def sample_user() -> dict:
    """Sample Clerk user data."""
    return {
        "id": "user_test123",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "username": "testuser",
        "profile_image_url": "https://example.com/avatar.png",
    }


# =============================================================================
# HELPER FIXTURES
# =============================================================================

@pytest.fixture
def dev_bypass_enabled() -> bool:
    """Check if developer bypass mode is enabled."""
    return DevBypassAuth.is_enabled()


@pytest.fixture(autouse=True)
def reset_singletons():
    """
    Reset singleton instances between tests.
    
    This ensures tests are isolated and don't share state.
    """
    yield
    reset_n8n_client()


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires external services)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow-running"
    )


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use uvloop if available for better async performance."""
    try:
        import uvloop
        return uvloop.EventLoopPolicy()
    except ImportError:
        import asyncio
        return asyncio.DefaultEventLoopPolicy()
