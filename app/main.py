from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.limiter import limiter
from app.db.supabase import create_service_client
from app.middleware.auth_middleware import AuthHijackMiddleware
from app.models.schemas import HealthResponse

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.settings = settings
    app.state.supabase_admin = await create_service_client(settings)
    app.state.httpx = httpx.AsyncClient(timeout=settings.request_timeout_seconds)
    yield
    await app.state.httpx.aclose()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(AuthHijackMiddleware, settings=settings)


@app.get("/health", response_model=HealthResponse)
async def healthcheck():
    return HealthResponse()


app.include_router(api_router)
