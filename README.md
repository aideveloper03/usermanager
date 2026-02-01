# N8N Orchestration Gateway

A production-ready, multi-tenant API gateway for private n8n instances. This gateway provides secure authentication, credit-based billing, and workflow orchestration using **Clerk Native Supabase Integration**.

## Version 1.1.0 - Native Clerk Integration

This version implements Clerk's native third-party auth provider integration with Supabase, providing:

- **Defense in Depth**: JWT validated by both Python gateway AND Supabase
- **Row-Level Security**: RLS policies enforced using `auth.jwt()->>'sub'` from Clerk tokens
- **Per-Request Authentication**: Authenticated Supabase clients with proper user context
- **Upgraded Dependencies**: supabase>=2.11.0, httpx>=0.28.0

## Overview

The N8N Orchestration Gateway acts as a secure proxy between your applications and private n8n instances. It handles:

- **Authentication**: Clerk JWT (with native Supabase RLS) and API key authentication
- **Authorization**: Multi-tenant organization-based access control with PostgreSQL RLS
- **Billing**: Credit-based pay-per-execution model with atomic transactions
- **Security**: HMAC signature validation, request fingerprinting, defense in depth
- **Credential Management**: Secure tenant credential storage in Supabase Vault

## Architecture

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│   Client    │────▶│  Gateway (FastAPI)  │────▶│    n8n      │
│  (Frontend) │     │                     │     │  Instance   │
└─────────────┘     │  - Auth Middleware  │     └─────────────┘
                    │  - Rate Limiting    │
                    │  - Credit Deduction │
                    │  - Logging          │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │      Supabase       │
                    │  - User Profiles    │
                    │  - Organizations    │
                    │  - Workflows        │
                    │  - Usage Logs       │
                    │  - Credentials Vault│
                    └─────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- Supabase project
- Clerk account
- n8n instance

### 1. Clone and Setup

```bash
git clone <repository>
cd n8n-gateway

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment

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

# Redis (for rate limiting)
REDIS_URL=redis://localhost:6379/0
```

### 3. Setup Database

Run the Supabase migrations in order:

```bash
# In Supabase SQL Editor, run:
# 1. supabase/migrations/01_initial_schema.sql
# 2. supabase/migrations/02_clerk_native_integration.sql
# 3. supabase/migrations/03_clerk_third_party_auth.sql
```

### 4. Configure Clerk as Supabase Third-Party Auth Provider

**This step is CRITICAL for the Clerk-Supabase integration to work.**

1. **In Clerk Dashboard**:
   - Go to **Integrations** → **Supabase**
   - Copy your Clerk **Issuer URL** (e.g., `https://xxx.clerk.accounts.dev`)
   - Note your **JWKS URL** (e.g., `https://xxx.clerk.accounts.dev/.well-known/jwks.json`)

2. **In Supabase Dashboard**:
   - Go to **Authentication** → **Providers**
   - Scroll to **Third-party Auth Providers**
   - Enable and configure:
     - **Auth Provider**: Clerk
     - **JWKS URL**: Your Clerk JWKS URL
     - **JWT Issuer**: Your Clerk issuer URL

This enables Supabase to validate Clerk JWTs directly and enforce RLS policies
using `auth.jwt()->>'sub'` to get the Clerk user ID.

### 5. Run with Docker Compose

```bash
docker compose up -d
```

The gateway will be available at `http://localhost:8000`.

### 6. Test the API

```bash
# Health check
curl http://localhost:8000/api/v1/health

# With authentication (requires valid Clerk JWT)
curl -H "Authorization: Bearer <token>" \
     http://localhost:8000/api/v1/organizations
```

## API Reference

### Authentication

The gateway supports two authentication methods:

#### JWT Authentication (Recommended)

Include a Clerk JWT token in the Authorization header:

```http
Authorization: Bearer <clerk-jwt-token>
```

#### API Key Authentication

Include your organization's API key:

```http
X-API-Key: gw_live_xxxxx
X-Tenant-ID: your-tenant-id
X-Timestamp: <unix-timestamp>
X-Signature: <hmac-signature>
```

### Endpoints

#### Health Checks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Basic health check |
| GET | `/api/v1/health/ready` | Readiness check (all dependencies) |
| GET | `/api/v1/health/live` | Liveness probe |

#### Organizations

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations` | List my organizations |
| GET | `/api/v1/organizations/{id}` | Get organization |
| PATCH | `/api/v1/organizations/{id}` | Update organization |
| POST | `/api/v1/organizations/{id}/credentials` | Store credentials |
| DELETE | `/api/v1/organizations/{id}/credentials` | Delete credentials |

#### Workflows

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/workflows` | Register workflow |
| GET | `/api/v1/workflows` | List workflows |
| GET | `/api/v1/workflows/{id}` | Get workflow |
| PATCH | `/api/v1/workflows/{id}` | Update workflow |
| POST | `/api/v1/workflows/{id}/activate` | Activate workflow |
| POST | `/api/v1/workflows/{id}/deactivate` | Deactivate workflow |

#### Execution

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/execute` | Execute workflow |
| POST | `/api/v1/execute/stream` | Execute with streaming |

### Execute Workflow

```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "uuid-of-workflow",
    "data": {
      "input": "your data here"
    },
    "metadata": {
      "source": "my-app"
    }
  }'
```

**Response:**

```json
{
  "success": true,
  "execution_id": "uuid",
  "status": "completed",
  "data": { "result": "..." },
  "credits_used": 1,
  "credits_remaining": 99,
  "execution_time_ms": 150
}
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SUPABASE_URL` | Yes | - | Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes | - | Supabase anonymous key |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | - | Supabase service role key |
| `CLERK_SECRET_KEY` | Yes | - | Clerk secret key |
| `CLERK_PUBLISHABLE_KEY` | Yes | - | Clerk publishable key |
| `CLERK_JWT_ISSUER` | Yes | - | Clerk JWT issuer URL |
| `CLERK_JWKS_URL` | Yes | - | Clerk JWKS URL |
| `N8N_BASE_URL` | Yes | - | n8n instance base URL |
| `N8N_INTERNAL_AUTH_SECRET` | Yes | - | Secret for n8n internal auth (64+ chars) |
| `N8N_API_KEY` | No | - | n8n API key for credential injection |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis URL for rate limiting |
| `ENABLE_RATE_LIMITING` | No | `true` | Enable rate limiting |
| `ENABLE_HMAC_VALIDATION` | No | `true` | Enable HMAC validation |
| `ENABLE_FINGERPRINTING` | No | `true` | Enable request fingerprinting |
| `DEV_SKIP_AUTH` | No | `false` | Skip auth in development |
| `ENVIRONMENT` | No | `production` | Environment name |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `CORS_ORIGINS` | No | - | Comma-separated allowed origins |

### Rate Limiting

Default rate limit: 100 requests per 60 seconds per tenant.

Configure with:
- `RATE_LIMIT_REQUESTS`: Requests per period
- `RATE_LIMIT_PERIOD`: Period in seconds

### Security Settings

| Setting | Description |
|---------|-------------|
| `HMAC_TIMESTAMP_TOLERANCE` | HMAC signature validity window (default: 300s) |
| `TRUSTED_PROXIES` | Comma-separated proxy IPs for correct client IP |

## Clerk + Supabase Native Integration

This gateway uses Clerk's **native third-party auth provider** integration with Supabase. This is the recommended approach (not the deprecated JWT template method).

### Architecture

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│   Client    │────▶│  Gateway (Python)   │────▶│  Supabase   │
│             │     │  Validates JWT      │     │  Also       │
│  (Clerk     │     │  via Clerk JWKS     │     │  Validates  │
│   Session)  │     └──────────┬──────────┘     │  JWT via    │
└─────────────┘                │                │  Clerk JWKS │
                               │ Same JWT       │  + RLS      │
                               └───────────────▶│             │
                                                └─────────────┘
```

### How It Works

1. **Client** authenticates with Clerk and gets a session token (JWT)
2. **Gateway** receives the JWT in the `Authorization: Bearer <token>` header
3. **Gateway** validates the JWT against Clerk's JWKS endpoint
4. **Gateway** creates a Supabase client passing the same JWT
5. **Supabase** validates the JWT again (defense in depth)
6. **RLS policies** use `auth.jwt()->>'sub'` to get the Clerk user ID

### Database Clients

The gateway uses two types of Supabase clients:

```python
# 1. Service Role Client (admin operations, bypasses RLS)
db = get_db_service()

# 2. Authenticated Client (user operations, enforces RLS)  
db = get_authenticated_db_service(clerk_jwt, user_id)
```

| Client Type | Use Case | RLS | When to Use |
|-------------|----------|-----|-------------|
| Service Role | Background jobs, webhooks, admin | Bypassed | Credit deduction, logging |
| Authenticated | User-initiated requests | Enforced | Reading user/org data |

### JWT Claims Available in RLS

```sql
-- Get Clerk user ID
auth.jwt()->>'sub'         -- Returns: user_xxx

-- Get organization ID
auth.jwt()->>'org_id'      -- Returns: org_xxx (if in org context)

-- Get organization role
auth.jwt()->>'org_role'    -- Returns: admin, member, etc.

-- Get email
auth.jwt()->>'email'       -- Returns: user@example.com
```

### RLS Policy Examples

```sql
-- Users can only read their own profile
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (id = (auth.jwt()->>'sub'));

-- Members can read their organization's workflows
CREATE POLICY "workflows_select_member" ON workflows
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = (auth.jwt()->>'sub')
        )
    );
```

### Setup Checklist

- [ ] Run all migrations (01, 02, 03)
- [ ] Configure Clerk integration in Clerk Dashboard
- [ ] Add Clerk as third-party auth provider in Supabase Dashboard
- [ ] Set `CLERK_JWKS_URL` and `CLERK_JWT_ISSUER` in environment
- [ ] Set both `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY`

## Development

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run with dev settings
ENVIRONMENT=development DEV_SKIP_AUTH=true python -m app.main
```

### Developer Bypass Mode

For local testing without valid Clerk tokens:

```bash
# Set environment
DEV_SKIP_AUTH=true
ENVIRONMENT=development

# Use headers to mock authentication
curl -X GET http://localhost:8000/api/v1/organizations \
  -H "X-Dev-User-ID: test_user" \
  -H "X-Dev-Org-ID: test_org"
```

**Warning**: Never enable `DEV_SKIP_AUTH` in production!

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific tests
pytest tests/test_health.py -v
```

### Code Quality

```bash
# Linting
ruff check app/

# Type checking
mypy app/

# Format code
ruff format app/
```

## Project Structure

```
n8n-gateway/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── endpoints/
│   │       │   ├── execute.py      # Workflow execution
│   │       │   ├── health.py       # Health checks
│   │       │   ├── internal.py     # n8n callbacks
│   │       │   ├── organizations.py
│   │       │   └── workflows.py
│   │       └── __init__.py         # Router setup
│   ├── core/
│   │   ├── config.py               # Settings management
│   │   ├── rate_limiter.py         # Rate limiting
│   │   └── security.py             # Security utilities
│   ├── middleware/
│   │   └── auth_middleware.py      # Authentication
│   ├── models/
│   │   └── schemas.py              # Pydantic models
│   ├── services/
│   │   ├── database.py             # Supabase operations
│   │   └── n8n_client.py           # n8n HTTP client
│   └── main.py                     # Application entry
├── frontend/                       # Next.js frontend
├── supabase/
│   └── migrations/                 # Database migrations
├── tests/                          # Test suite
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Security Considerations

### Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DEBUG=false`
- [ ] Set `DEV_SKIP_AUTH=false`
- [ ] Use 64+ character `N8N_INTERNAL_AUTH_SECRET`
- [ ] Configure `CORS_ORIGINS` explicitly
- [ ] Enable rate limiting
- [ ] Enable HMAC validation
- [ ] Use HTTPS for all endpoints
- [ ] Rotate API keys periodically
- [ ] Monitor security logs

### HMAC Signature Validation

For API key authentication, requests should include:

```javascript
const crypto = require('crypto');

const timestamp = Math.floor(Date.now() / 1000).toString();
const body = JSON.stringify(requestBody);
const signature = crypto
  .createHmac('sha256', clientSecret)
  .update(timestamp + body)
  .digest('hex');

headers = {
  'X-API-Key': apiKey,
  'X-Timestamp': timestamp,
  'X-Signature': signature,
  'X-Tenant-ID': tenantId
};
```

### Request Fingerprinting

The gateway creates fingerprints from:
- Client IP address
- User-Agent header
- Tenant ID

This helps detect suspicious activity like token theft.

## Troubleshooting

### Common Issues

**1. JWT Verification Failed**
- Check `CLERK_JWT_ISSUER` matches your Clerk instance
- Verify `CLERK_JWKS_URL` is accessible
- Ensure token hasn't expired

**2. Organization Not Found**
- User must be a member of the organization
- Check organization is active (`is_active=true`)

**3. Insufficient Credits**
- Organization needs credits to execute workflows
- Add credits via the API or admin panel

**4. n8n Connection Failed**
- Verify `N8N_BASE_URL` is correct
- Check n8n instance is running
- Ensure `N8N_INTERNAL_AUTH_SECRET` matches n8n config

### Debug Mode

Enable detailed logging:

```bash
LOG_LEVEL=DEBUG
LOG_FORMAT=text
```

### Health Check

```bash
# Basic health
curl http://localhost:8000/api/v1/health

# Detailed readiness (checks all dependencies)
curl http://localhost:8000/api/v1/health/ready
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Run linting: `ruff check app/`
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Open a GitHub issue
- Check existing documentation in `/docs`
- Review the API documentation at `/docs` (when running locally)
