"""API v1 module."""

from fastapi import APIRouter

from app.api.v1.endpoints import execute, health, internal, organizations, workflows

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(execute.router, prefix="/execute", tags=["Execute"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(workflows.router, prefix="/workflows", tags=["Workflows"])
api_router.include_router(internal.router, prefix="/internal", tags=["Internal"])
