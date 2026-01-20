from fastapi import APIRouter

from app.api.v1.endpoints import execute, internal

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(execute.router, tags=["execute"])
api_router.include_router(internal.router, tags=["internal"])
