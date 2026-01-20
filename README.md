# B2B Orchestration Gateway

Production-ready FastAPI wrapper that acts as a hardened, multi-tenant proxy for a private n8n
instance. It integrates Clerk JWT authentication with Supabase RLS and Supabase Vault for tenant
secret management.

## Features

- Multi-tenant organization model with credit-based usage
- Clerk JWT validation via clerk-sdk-python (backend API)
- Supabase RLS with Vault-backed tenant secrets
- Anti-hijacking HMAC verification (timestamp + request body)
- IP + User-Agent + Tenant fingerprinting with suspicious logging
- Redis-backed SlowAPI sliding-window rate limiting
- Streaming proxy to n8n webhooks

## Project Structure

```
app/
  api/v1/endpoints/execute.py
  api/v1/endpoints/internal.py
  core/config.py
  core/security.py
  middleware/auth_middleware.py
  models/schemas.py
supabase/migrations/01_initial_schema.sql
docs/
  SUPABASE.md
  N8N.md
```

## Requirements

- Python 3.12+
- Redis
- Supabase project with Vault enabled
- n8n private instance

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Environment Variables

Create a `.env` file (or inject env vars in your deployment):

```
SUPABASE_URL=...
SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...

CLERK_JWKS_URL=...
CLERK_ISSUER=...
CLERK_AUDIENCE=...

N8N_WEBHOOK_URL=...
N8N_INTERNAL_SECRET=...

REDIS_URL=redis://localhost:6379/0
RATE_LIMIT=30/minute
HMAC_MAX_AGE_SECONDS=300
REQUEST_TIMEOUT_SECONDS=60
ALLOWED_ORIGINS=["https://yourapp.com"]
```

## API Usage

### POST `/api/v1/execute`

Headers:

- `Authorization: Bearer <Clerk JWT>`
- `X-Tenant-ID: <tenant_id>`
- `X-Timestamp: <unix_seconds>`
- `X-Signature: <hmac_sha256(timestamp + raw_body)>`

Body:

```json
{
  "payload": {
    "input": "..."
  },
  "credits": 1
}
```

The gateway deducts credits, injects tenant secrets from the Vault, and streams the n8n response.

### POST `/api/v1/internal/log-error`

Used by n8n error workflows.

Headers:

- `X-N8N-Internal-Auth: <N8N_INTERNAL_SECRET>`

Body:

```json
{
  "org_id": "<org_uuid>",
  "workflow_id": "optional",
  "error_message": "optional",
  "metadata": {
    "additional": "context"
  }
}
```

## Security Notes

- HMAC uses per-tenant `client_secret` stored in Supabase Vault.
- Requests older than 300 seconds are rejected.
- Fingerprints are stored in `security_logs` with `baseline` or `suspicious` status.

## Documentation

- [Supabase Setup](docs/SUPABASE.md)
- [n8n Connection](docs/N8N.md)