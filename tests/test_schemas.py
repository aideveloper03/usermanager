"""
Tests for Pydantic schemas and validation.
"""

import pytest
from uuid import uuid4
from datetime import datetime

from pydantic import ValidationError

from app.models.schemas import (
    ExecuteRequest,
    ExecuteResponse,
    ExecutionStatus,
    OrganizationCreate,
    WorkflowCreate,
    ProfileCreate,
    PaginationParams,
    PaginatedResponse,
)


class TestExecuteRequest:
    """Tests for ExecuteRequest schema."""
    
    def test_valid_request(self):
        """Test valid execute request."""
        request = ExecuteRequest(
            workflow_id=uuid4(),
            data={"input": "test"},
            metadata={"source": "test"}
        )
        
        assert request.workflow_id is not None
        assert request.data == {"input": "test"}
    
    def test_sanitizes_xss(self):
        """Test that XSS payloads are sanitized."""
        request = ExecuteRequest(
            workflow_id=uuid4(),
            data={"input": "<script>alert('xss')</script>test"}
        )
        
        assert "<script>" not in request.data["input"]
        assert "test" in request.data["input"]
    
    def test_optional_callback_url(self):
        """Test optional callback URL validation."""
        request = ExecuteRequest(
            workflow_id=uuid4(),
            data={},
            callback_url="https://example.com/callback"
        )
        
        assert str(request.callback_url) == "https://example.com/callback"
    
    def test_invalid_callback_url(self):
        """Test invalid callback URL is rejected."""
        with pytest.raises(ValidationError):
            ExecuteRequest(
                workflow_id=uuid4(),
                data={},
                callback_url="not-a-url"
            )
    
    def test_timeout_bounds(self):
        """Test timeout override bounds."""
        # Valid timeout
        request = ExecuteRequest(
            workflow_id=uuid4(),
            data={},
            timeout_override=300
        )
        assert request.timeout_override == 300
        
        # Too low
        with pytest.raises(ValidationError):
            ExecuteRequest(
                workflow_id=uuid4(),
                data={},
                timeout_override=5
            )
        
        # Too high
        with pytest.raises(ValidationError):
            ExecuteRequest(
                workflow_id=uuid4(),
                data={},
                timeout_override=1000
            )


class TestExecuteResponse:
    """Tests for ExecuteResponse schema."""
    
    def test_successful_response(self):
        """Test successful execution response."""
        response = ExecuteResponse(
            success=True,
            execution_id=uuid4(),
            status=ExecutionStatus.COMPLETED,
            data={"result": "success"},
            credits_used=1,
            credits_remaining=99,
            execution_time_ms=150
        )
        
        assert response.success is True
        assert response.status == ExecutionStatus.COMPLETED
    
    def test_failed_response(self):
        """Test failed execution response."""
        response = ExecuteResponse(
            success=False,
            execution_id=uuid4(),
            status=ExecutionStatus.FAILED,
            error="Workflow execution failed",
            credits_used=0
        )
        
        assert response.success is False
        assert response.error is not None


class TestOrganizationCreate:
    """Tests for OrganizationCreate schema."""
    
    def test_valid_organization(self):
        """Test valid organization creation."""
        org = OrganizationCreate(
            name="Test Organization",
            tenant_id="test-tenant-123"
        )
        
        assert org.name == "Test Organization"
        assert org.tenant_id == "test-tenant-123"
    
    def test_tenant_id_pattern(self):
        """Test tenant ID pattern validation."""
        # Valid tenant IDs
        OrganizationCreate(name="Test", tenant_id="valid-tenant")
        OrganizationCreate(name="Test", tenant_id="tenant123")
        
        # Invalid tenant IDs
        with pytest.raises(ValidationError):
            OrganizationCreate(name="Test", tenant_id="Invalid_Tenant")  # Uppercase
        
        with pytest.raises(ValidationError):
            OrganizationCreate(name="Test", tenant_id="ab")  # Too short
    
    def test_sanitizes_name(self):
        """Test organization name sanitization."""
        org = OrganizationCreate(
            name="<b>Test</b> Organization",
            tenant_id="test-tenant"
        )
        
        assert "<b>" not in org.name


class TestWorkflowCreate:
    """Tests for WorkflowCreate schema."""
    
    def test_valid_workflow(self):
        """Test valid workflow creation."""
        workflow = WorkflowCreate(
            name="Test Workflow",
            n8n_workflow_id="n8n-123",
            n8n_webhook_path="/webhook/test"
        )
        
        assert workflow.name == "Test Workflow"
        assert workflow.is_active is True
        assert workflow.credits_per_execution == 1
    
    def test_custom_settings(self):
        """Test workflow with custom settings."""
        workflow = WorkflowCreate(
            name="Custom Workflow",
            n8n_workflow_id="n8n-456",
            n8n_webhook_path="/webhook/custom",
            credits_per_execution=5,
            timeout_seconds=120
        )
        
        assert workflow.credits_per_execution == 5
        assert workflow.timeout_seconds == 120


class TestPagination:
    """Tests for pagination schemas."""
    
    def test_default_pagination(self):
        """Test default pagination values."""
        params = PaginationParams()
        
        assert params.page == 1
        assert params.page_size == 20
        assert params.offset == 0
    
    def test_custom_pagination(self):
        """Test custom pagination values."""
        params = PaginationParams(page=3, page_size=50)
        
        assert params.page == 3
        assert params.page_size == 50
        assert params.offset == 100
    
    def test_pagination_bounds(self):
        """Test pagination bounds validation."""
        # Page must be >= 1
        with pytest.raises(ValidationError):
            PaginationParams(page=0)
        
        # Page size must be <= 100
        with pytest.raises(ValidationError):
            PaginationParams(page_size=200)
    
    def test_paginated_response(self):
        """Test paginated response creation."""
        items = [{"id": i} for i in range(20)]
        
        response = PaginatedResponse.create(
            items=items,
            total=100,
            page=2,
            page_size=20
        )
        
        assert response.total == 100
        assert response.page == 2
        assert response.total_pages == 5
        assert len(response.items) == 20
