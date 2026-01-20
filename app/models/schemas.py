from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import Field

from app.core.security import SanitizedModel


class ExecuteRequest(SanitizedModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    credits: int = Field(default=1, ge=1)


class ErrorLogRequest(SanitizedModel):
    org_id: str
    workflow_id: Optional[str] = None
    status: str = Field(default="failed")
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(SanitizedModel):
    status: str = Field(default="ok")
