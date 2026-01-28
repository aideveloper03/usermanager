# N8N Orchestration Gateway

A production-ready, multi-tenant API gateway for orchestrating n8n workflows with enterprise-grade security, credit-based billing, and dynamic credential injection.

## Overview

The N8N Orchestration Gateway provides a secure wrapper around private n8n instances, enabling:

- **Multi-tenant Architecture**: Organizations with isolated API keys, credentials, and billing
- **Credit-based Billing**: Pay-per-execution model with atomic credit deduction
- **Secure Authentication**: Clerk JWT validation with native Supabase integration
- **Dynamic Credential Injection**: Tenant-specific secrets from Supabase Vault
- **Anti-Hijacking Protection**: HMAC signature validation and request fingerprinting
- **Developer Mode**: Auth bypass for local development and testing

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Frontend UI   │────▶│  Gateway API     │────▶│  n8n Instance   │
│   (Next.js +    │     │  (FastAPI)       │     │  (Workflows)    │
│    Clerk)       │     │                  │     │                 │
└─────────────────┘     └────────┬─────────┘     └─────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
              ┌─────▼─────┐           ┌───────▼───────┐
              │  Supabase │           │    Redis      │
              │  (DB +    │           │  (Rate Limit) │
              │   Vault)  │           │               │
              └───────────┘           └───────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for frontend development)
- Python 3.12+ (for backend development)
- Supabase account
- Clerk account
- n8n instance

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd n8n-orchestration-gateway

# Copy environment files
cp .env.example .env
cp frontend/.env.example frontend/.env.local
```

### 2. Configure Environment Variables

Edit `.env` with your credentials:

```bash
# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Clerk
CLERK_SECRET_KEY=sk_test_xxxxx
CLERK_PUBLISHABLE_KEY=pk_test_xxxxx
CLERK_JWT_ISSUER=https://your-instance.clerk.accounts.dev
CLERK_JWKS_URL=https://your-instance.clerk.accounts.dev/.well-known/jwks.json

# n8n
N8N_BASE_URL=https://your-n8n-instance.com
N8N_INTERNAL_AUTH_SECRET=your-64-character-secret
```

### 3. Apply Database Migrations

Run the SQL migrations in your Supabase dashboard:

```bash
# In Supabase SQL Editor, run:
# 1. supabase/migrations/01_initial_schema.sql
# 2. supabase/migrations/02_clerk_native_integration.sql
```

### 4. Start Services

```bash
# Development mode (with Docker)
docker compose up -d

# Or run locally
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 5. Access the UI

- Frontend: http://localhost:3000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/api/v1/health

## Development

### Developer Bypass Mode

For local development without Clerk authentication:

```bash
# Set in .env
DEV_SKIP_AUTH=true
DEV_DEFAULT_USER_ID=dev_user_001
DEV_DEFAULT_ORG_ID=dev_org_001
```

Then use headers to mock authentication:

```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "X-Dev-User-ID: test_user" \
  -H "X-Dev-Org-ID: test_org" \
  -H "Content-Type: application/json" \
  -d '{"workflow_id": "xxx", "data": {}}'
```

### Running Tests

```bash
# Unit tests
pytest tests/ -v

# End-to-end tests (with dev bypass)
python tests/local_test.py

# Specific test
python tests/local_test.py --test test_health_check
```

## Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [Supabase Setup](docs/SUPABASE_SETUP.md) - Database configuration guide
- [n8n Setup](docs/N8N_SETUP.md) - n8n integration guide
- [Clerk Integration](docs/CLERK_INTEGRATION.md) - Authentication setup
- [Code Structure](docs/CODE_STRUCTURE.md) - Architecture overview
- [Workflow Guide](docs/WORKFLOW_GUIDE.md) - Workflow creation guide

## Security

### Authentication Methods

1. **Clerk JWT** (recommended for user-facing applications)
   ```bash
   Authorization: Bearer <clerk-jwt-token>
   ```

2. **API Key** (for server-to-server communication)
   ```bash
   X-API-Key: gw_live_xxxx
   X-Timestamp: <unix-timestamp>
   X-Signature: <hmac-sha256-signature>
   ```

### HMAC Signature

For API key authentication, compute HMAC-SHA256:
```
signature = HMAC-SHA256(client_secret, timestamp + request_body)
```

### Dynamic Credentials

Tenant credentials are stored in Supabase Vault and injected at runtime:

1. **Simple Injection**: Credentials passed in webhook payload
2. **Dynamic Injection**: Credentials patched into n8n via REST API with advisory locks

## Project Structure

```
.
├── app/                    # FastAPI backend
│   ├── api/v1/            # API routes
│   ├── core/              # Config, security, rate limiting
│   ├── middleware/        # Auth, HMAC, fingerprinting
│   ├── models/            # Pydantic schemas
│   └── services/          # Database, n8n client
├── frontend/              # Next.js frontend
│   └── src/
│       ├── app/           # Pages and layouts
│       └── components/    # React components
├── supabase/
│   └── migrations/        # SQL migrations
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
