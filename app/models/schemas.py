"""
Pydantic V2 models for request/response validation.

This module defines all data models used by the API with:
- Strict type validation
- Custom validators for input sanitization
- Comprehensive documentation
"""

from datetime import datetime
from enum import Enum
from typing import Any, Annotated
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    EmailStr,
    HttpUrl,
    field_validator,
    model_validator,
)

from app.core.security import sanitizer


# =============================================================================
# BASE MODELS
# =============================================================================


class SanitizedModel(BaseModel):
    """
    Base model that automatically sanitizes all string fields.
    
    All models that accept user input should inherit from this class
    to ensure XSS and injection payloads are stripped.
    """
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_min_length=0,
        extra="forbid",  # Reject unknown fields
    )
    
    @model_validator(mode="after")
    def sanitize_all_strings(self) -> "SanitizedModel":
        """Sanitize all string fields after validation."""
        for field_name, field_value in self.__dict__.items():
            if isinstance(field_value, str):
                setattr(self, field_name, sanitizer.sanitize_string(field_value))
            elif isinstance(field_value, dict):
                setattr(self, field_name, sanitizer.sanitize_dict(field_value))
            elif isinstance(field_value, list):
                setattr(self, field_name, sanitizer.sanitize_list(field_value))
        return self


class TimestampedModel(BaseModel):
    """Base model with timestamp fields."""
    
    created_at: datetime = Field(description="Creation timestamp")
    updated_at: datetime | None = Field(default=None, description="Last update timestamp")


# =============================================================================
# ENUMS
# =============================================================================


class ExecutionStatus(str, Enum):
    """Status of a workflow execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class PlanType(str, Enum):
    """Organization plan types."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class InvoiceStatus(str, Enum):
    """Invoice status types."""
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class MemberRole(str, Enum):
    """Organization member roles."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class SecurityEventType(str, Enum):
    """Security event types for logging."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    SUSPICIOUS_FINGERPRINT = "suspicious_fingerprint"
    HMAC_VALIDATION_FAILED = "hmac_validation_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    TOKEN_EXPIRED = "token_expired"
    INVALID_API_KEY = "invalid_api_key"


# =============================================================================
# EXECUTE ENDPOINT MODELS
# =============================================================================


class ExecuteRequest(SanitizedModel):
    """
    Request body for workflow execution.
    
    This is the main payload sent by clients to trigger n8n workflows.
    All string fields are automatically sanitized to prevent XSS.
    """
    
    workflow_id: UUID = Field(
        description="UUID of the workflow to execute"
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Input data to pass to the n8n workflow"
    )
    callback_url: HttpUrl | None = Field(
        default=None,
        description="Optional webhook URL to receive execution results"
    )
    timeout_override: int | None = Field(
        default=None,
        ge=10,
        le=600,
        description="Custom timeout in seconds (10-600)"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata for logging/tracking"
    )
    
    @field_validator("data", mode="after")
    @classmethod
    def sanitize_data(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Ensure the data payload is sanitized."""
        return sanitizer.sanitize_dict(v)
    
    @field_validator("metadata", mode="after")
    @classmethod
    def sanitize_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Ensure metadata is sanitized."""
        return sanitizer.sanitize_dict(v)


class ExecuteResponse(BaseModel):
    """Response from workflow execution endpoint."""
    
    model_config = ConfigDict(from_attributes=True)
    
    success: bool = Field(description="Whether the execution was initiated successfully")
    execution_id: UUID | None = Field(
        default=None,
        description="UUID of the usage log entry for tracking"
    )
    status: ExecutionStatus = Field(description="Current execution status")
    data: dict[str, Any] | None = Field(
        default=None,
        description="Response data from the n8n workflow"
    )
    credits_used: int = Field(default=0, description="Credits consumed by this execution")
    credits_remaining: int | None = Field(
        default=None,
        description="Organization's remaining credit balance"
    )
    execution_time_ms: int | None = Field(
        default=None,
        description="Execution time in milliseconds"
    )
    error: str | None = Field(default=None, description="Error message if execution failed")
    
    @field_validator("error", mode="before")
    @classmethod
    def sanitize_error(cls, v: str | None) -> str | None:
        """Sanitize error messages."""
        if v is not None:
            return sanitizer.sanitize_string(v)
        return v


# =============================================================================
# PROFILE MODELS
# =============================================================================


class ProfileBase(SanitizedModel):
    """Base profile fields."""
    
    name: str | None = Field(default=None, max_length=255, description="Full name")
    username: str | None = Field(
        default=None,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique username"
    )
    company_name: str | None = Field(default=None, max_length=255, description="Company name")


class ProfileCreate(ProfileBase):
    """Profile creation request (synced from Clerk)."""
    
    id: str = Field(description="Clerk user ID", min_length=1)
    email: EmailStr = Field(description="Email address")
    email_verified: bool = Field(default=False, description="Email verification status")
    phone: str | None = Field(default=None, max_length=20, description="Phone number")
    phone_verified: bool = Field(default=False, description="Phone verification status")
    avatar_url: HttpUrl | None = Field(default=None, description="Profile picture URL")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ProfileUpdate(ProfileBase):
    """Profile update request."""
    
    phone: str | None = Field(default=None, max_length=20, description="Phone number")
    avatar_url: HttpUrl | None = Field(default=None, description="Profile picture URL")
    metadata: dict[str, Any] | None = Field(default=None, description="Additional metadata")


class ProfileResponse(ProfileBase, TimestampedModel):
    """Profile response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: str = Field(description="Clerk user ID")
    email: EmailStr = Field(description="Email address")
    email_verified: bool = Field(description="Email verification status")
    phone: str | None = Field(default=None, description="Phone number")
    phone_verified: bool = Field(default=False, description="Phone verification status")
    avatar_url: str | None = Field(default=None, description="Profile picture URL")


# =============================================================================
# ORGANIZATION MODELS
# =============================================================================


class OrganizationBase(SanitizedModel):
    """Base organization fields."""
    
    name: str = Field(min_length=1, max_length=255, description="Organization name")


class OrganizationCreate(OrganizationBase):
    """Organization creation request."""
    
    tenant_id: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[a-z0-9-]+$",
        description="Unique tenant identifier (lowercase, alphanumeric with hyphens)"
    )
    plan_type: PlanType = Field(default=PlanType.FREE, description="Subscription plan")
    settings: dict[str, Any] = Field(default_factory=dict, description="Organization settings")


class OrganizationUpdate(SanitizedModel):
    """Organization update request."""
    
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Organization name"
    )
    settings: dict[str, Any] | None = Field(default=None, description="Organization settings")


class OrganizationResponse(OrganizationBase, TimestampedModel):
    """Organization response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="Organization UUID")
    tenant_id: str = Field(description="Unique tenant identifier")
    api_key_prefix: str = Field(description="API key prefix for identification")
    credits: int = Field(description="Current credit balance")
    plan_type: PlanType = Field(description="Subscription plan")
    is_active: bool = Field(description="Whether the organization is active")
    settings: dict[str, Any] = Field(default_factory=dict, description="Organization settings")


class OrganizationWithSecrets(OrganizationResponse):
    """Organization response with API key (only returned on creation)."""
    
    api_key: str = Field(description="Full API key (only shown once)")
    client_secret: str = Field(description="Client secret for HMAC signing (only shown once)")


# =============================================================================
# WORKFLOW MODELS
# =============================================================================


class WorkflowBase(SanitizedModel):
    """Base workflow fields."""
    
    name: str = Field(min_length=1, max_length=255, description="Workflow name")
    description: str | None = Field(
        default=None,
        max_length=1000,
        description="Workflow description"
    )


class WorkflowCreate(WorkflowBase):
    """Workflow creation request."""
    
    n8n_workflow_id: str = Field(
        min_length=1,
        max_length=100,
        description="n8n workflow ID"
    )
    n8n_webhook_path: str = Field(
        min_length=1,
        max_length=255,
        description="n8n webhook path"
    )
    is_active: bool = Field(default=True, description="Whether the workflow is active")
    credits_per_execution: int = Field(
        default=1,
        ge=0,
        description="Credits consumed per execution"
    )
    timeout_seconds: int = Field(
        default=300,
        ge=10,
        le=600,
        description="Execution timeout in seconds"
    )
    settings: dict[str, Any] = Field(default_factory=dict, description="Workflow settings")


class WorkflowUpdate(SanitizedModel):
    """Workflow update request."""
    
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Workflow name"
    )
    description: str | None = Field(default=None, max_length=1000, description="Description")
    is_active: bool | None = Field(default=None, description="Whether the workflow is active")
    credits_per_execution: int | None = Field(
        default=None,
        ge=0,
        description="Credits per execution"
    )
    timeout_seconds: int | None = Field(default=None, ge=10, le=600, description="Timeout")
    settings: dict[str, Any] | None = Field(default=None, description="Workflow settings")


class WorkflowResponse(WorkflowBase, TimestampedModel):
    """Workflow response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="Workflow UUID")
    organization_id: UUID = Field(description="Organization UUID")
    n8n_workflow_id: str = Field(description="n8n workflow ID")
    n8n_webhook_path: str = Field(description="n8n webhook path")
    is_active: bool = Field(description="Whether the workflow is active")
    credits_per_execution: int = Field(description="Credits consumed per execution")
    timeout_seconds: int = Field(description="Execution timeout in seconds")
    settings: dict[str, Any] = Field(default_factory=dict, description="Workflow settings")


# =============================================================================
# USAGE LOG MODELS
# =============================================================================


class UsageLogResponse(BaseModel):
    """Usage log response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="Usage log UUID")
    organization_id: UUID = Field(description="Organization UUID")
    workflow_id: UUID | None = Field(default=None, description="Workflow UUID")
    profile_id: str | None = Field(default=None, description="User profile ID")
    credits_used: int = Field(description="Credits consumed")
    status: ExecutionStatus = Field(description="Execution status")
    execution_time_ms: int | None = Field(default=None, description="Execution time in ms")
    error_message: str | None = Field(default=None, description="Error message if failed")
    created_at: datetime = Field(description="Execution start time")
    completed_at: datetime | None = Field(default=None, description="Execution completion time")


class UsageStats(BaseModel):
    """Usage statistics for an organization."""
    
    total_executions: int = Field(description="Total number of executions")
    successful_executions: int = Field(description="Number of successful executions")
    failed_executions: int = Field(description="Number of failed executions")
    total_credits_used: int = Field(description="Total credits consumed")
    average_execution_time_ms: float | None = Field(
        default=None,
        description="Average execution time in milliseconds"
    )
    period_start: datetime = Field(description="Start of statistics period")
    period_end: datetime = Field(description="End of statistics period")


# =============================================================================
# INVOICE MODELS
# =============================================================================


class InvoiceResponse(BaseModel):
    """Invoice response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="Invoice UUID")
    organization_id: UUID = Field(description="Organization UUID")
    amount: float = Field(description="Invoice amount")
    currency: str = Field(description="Currency code")
    credits_purchased: int = Field(description="Credits purchased")
    status: InvoiceStatus = Field(description="Invoice status")
    billing_date: datetime = Field(description="Billing date")
    paid_at: datetime | None = Field(default=None, description="Payment date")
    created_at: datetime = Field(description="Creation timestamp")


# =============================================================================
# SECURITY LOG MODELS
# =============================================================================


class SecurityLogResponse(BaseModel):
    """Security log response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="Log entry UUID")
    organization_id: UUID | None = Field(default=None, description="Organization UUID")
    profile_id: str | None = Field(default=None, description="User profile ID")
    event_type: SecurityEventType = Field(description="Security event type")
    severity: str = Field(description="Event severity (info, warning, critical)")
    ip_address: str | None = Field(default=None, description="Client IP address")
    request_path: str | None = Field(default=None, description="Request path")
    request_method: str | None = Field(default=None, description="HTTP method")
    details: dict[str, Any] = Field(default_factory=dict, description="Event details")
    created_at: datetime = Field(description="Event timestamp")


# =============================================================================
# API KEY MODELS
# =============================================================================


class APIKeyCreate(SanitizedModel):
    """API key creation request."""
    
    name: str = Field(min_length=1, max_length=100, description="Key name/description")
    permissions: dict[str, list[str]] = Field(
        default_factory=lambda: {"workflows": ["*"]},
        description="Permission scopes"
    )
    expires_at: datetime | None = Field(default=None, description="Expiration timestamp")


class APIKeyResponse(BaseModel):
    """API key response model."""
    
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID = Field(description="API key UUID")
    organization_id: UUID = Field(description="Organization UUID")
    name: str = Field(description="Key name")
    key_prefix: str = Field(description="Key prefix for identification")
    permissions: dict[str, list[str]] = Field(description="Permission scopes")
    expires_at: datetime | None = Field(default=None, description="Expiration timestamp")
    last_used_at: datetime | None = Field(default=None, description="Last usage timestamp")
    is_active: bool = Field(description="Whether the key is active")
    created_at: datetime = Field(description="Creation timestamp")


class APIKeyWithSecret(APIKeyResponse):
    """API key response with the actual key (only shown once)."""
    
    key: str = Field(description="Full API key (only shown once)")


# =============================================================================
# HEALTH & STATUS MODELS
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = Field(description="Service status")
    version: str = Field(description="Application version")
    environment: str = Field(description="Environment name")
    timestamp: datetime = Field(description="Current server time")
    checks: dict[str, bool] = Field(
        default_factory=dict,
        description="Individual health check results"
    )


class ErrorResponse(BaseModel):
    """Standard error response."""
    
    error: str = Field(description="Error type/code")
    message: str = Field(description="Human-readable error message")
    details: dict[str, Any] | None = Field(default=None, description="Additional error details")
    request_id: str | None = Field(default=None, description="Request ID for tracking")


# =============================================================================
# PAGINATION MODELS
# =============================================================================


class PaginationParams(BaseModel):
    """Pagination parameters."""
    
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    
    @property
    def offset(self) -> int:
        """Calculate offset for database queries."""
        return (self.page - 1) * self.page_size


class PaginatedResponse(BaseModel):
    """Generic paginated response wrapper."""
    
    items: list[Any] = Field(description="List of items")
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")
    
    @classmethod
    def create(
        cls,
        items: list[Any],
        total: int,
        page: int,
        page_size: int
    ) -> "PaginatedResponse":
        """Create a paginated response."""
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )


# =============================================================================
# INTERNAL WEBHOOK MODELS
# =============================================================================


class N8NErrorCallback(SanitizedModel):
    """Callback payload from n8n error workflows."""
    
    workflow_id: str = Field(description="n8n workflow ID that failed")
    execution_id: str = Field(description="n8n execution ID")
    error_message: str = Field(max_length=5000, description="Error message")
    error_stack: str | None = Field(
        default=None,
        max_length=10000,
        description="Error stack trace"
    )
    timestamp: datetime = Field(description="Error timestamp")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class InternalLogRequest(SanitizedModel):
    """Internal error logging request from n8n."""
    
    usage_log_id: UUID = Field(description="Usage log ID to update")
    status: ExecutionStatus = Field(description="New status")
    error_message: str | None = Field(
        default=None,
        max_length=5000,
        description="Error message"
    )
    execution_time_ms: int | None = Field(default=None, description="Execution time in ms")
    response_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Response metadata"
    )
