from __future__ import annotations

from supabase import AsyncClient, create_async_client

from app.core.config import Settings


async def create_service_client(settings: Settings) -> AsyncClient:
    return await create_async_client(str(settings.supabase_url), settings.supabase_service_role_key)


async def create_user_client(settings: Settings, token: str) -> AsyncClient:
    client = await create_async_client(str(settings.supabase_url), settings.supabase_anon_key)
    try:
        client.postgrest.auth(token)
    except Exception:
        pass
    return client
