# N8N Orchestration Gateway Documentation

## Overview

The N8N Orchestration Gateway is a production-ready, multi-tenant API wrapper for private n8n instances. It provides secure workflow execution with credit-based billing, Clerk authentication, and tenant credential isolation.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Authentication](#authentication)
3. [API Reference](#api-reference)
4. [Security](#security)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Development](#development)

---

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   Client App    │────▶│  Orchestration       │────▶│   Private n8n   │
│  (Frontend UI)  │     │  Gateway (FastAPI)   │     │   Instance      │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
        │                        │                           │
        │                        │                           │
        ▼                        ▼                           │
┌─────────────────┐     ┌──────────────────────┐            │
│     Clerk       │     │      Supabase        │◀───────────┘
│  (Auth Provider)│     │  (Database + Vault)  │
└─────────────────┘     └──────────────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **FastAPI Gateway** | Main API server handling authentication, authorization, and request routing |
| **Clerk** | User authentication and organization management |
| **Supabase** | PostgreSQL database with Row-Level Security and encrypted credential storage |
| **n8n** | Private workflow automation instance |
| **Redis** | Rate limiting storage (optional) |

### Key Features

- **Multi-tenant Architecture**: Organizations have isolated API keys and credentials
- **Credit-based Billing**: Pay-per-execution model with atomic credit deduction
- **Secure Authentication**: Clerk JWT validation with official SDK
- **Credential Injection**: Secure tenant credential storage in Supabase Vault
- **Rate Limiting**: Redis-backed sliding window rate limiting
- **Input Sanitization**: Automatic XSS payload stripping

---

## Authentication

### Methods

The gateway supports two authentication methods:

#### 1. Clerk JWT (Recommended)

Include the Clerk session token in the Authorization header:

```http
Authorization: Bearer <clerk_session_token>
```

The JWT is verified using the official Clerk SDK with JWKS rotation support.

#### 2. API Key

Include your organization's API key in the X-API-Key header:

```http
X-API-Key: gw_live_xxxxxxxxxxxxx
```

**Optional Headers for API Key Auth:**
- `X-Timestamp`: Unix timestamp for replay protection
- `X-Tenant-ID`: Organization tenant identifier

### Developer Bypass Mode

For local development, set `DEV_SKIP_AUTH=true` in your environment. Then use these headers:

```http
X-Dev-User-ID: dev_user_001
X-Dev-Org-ID: dev_org_001
X-Dev-Role: admin
```

⚠️ **Never enable in production!**

---

## API Reference

### Base URL

```
https://your-gateway.com/api/v1
```

### Endpoints

#### Health Check

```http
GET /health
```

Returns service health status.

#### Execute Workflow

```http
POST /execute
Content-Type: application/json
Authorization: Bearer <token>

{
  "workflow_id": "uuid",
  "data": { "key": "value" },
  "timeout_override": 300
}
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
  "execution_time_ms": 1234
}
```

#### Organizations

```http
POST /organizations              # Create organization
GET /organizations               # List my organizations
GET /organizations/{org_id}      # Get organization details
PATCH /organizations/{org_id}    # Update organization
POST /organizations/{org_id}/credentials  # Store credentials
DELETE /organizations/{org_id}/credentials  # Delete credentials
GET /organizations/{org_id}/usage  # Get usage logs
```

#### Workflows

```http
POST /workflows?org_id=uuid      # Create workflow
GET /workflows?org_id=uuid       # List workflows
GET /workflows/{id}              # Get workflow
PATCH /workflows/{id}            # Update workflow
POST /workflows/{id}/activate    # Activate workflow
POST /workflows/{id}/deactivate  # Deactivate workflow
```

---

## Security

### Authentication Flow

```
1. Client sends request with JWT or API Key
2. Gateway validates authentication:
   - JWT: Verified using Clerk SDK (JWKS)
   - API Key: Hash compared against database
3. User/Organization context extracted from claims
4. Request processed with proper authorization
```

### Data Protection

| Data | Protection |
|------|------------|
| API Keys | SHA-256 hashed before storage |
| Client Secrets | SHA-256 hashed (used for audit trail) |
| Tenant Credentials | Encrypted in Supabase Vault |
| JWT Tokens | RS256 signed, verified via JWKS |
| User Input | Sanitized with bleach (XSS protection) |

### Row-Level Security (RLS)

All database tables have RLS policies:

```sql
-- Users can only see their own profile
CREATE POLICY "profiles_select_own" ON profiles
  FOR SELECT USING (id = auth.clerk_user_id());

-- Members can only see their organization's data
CREATE POLICY "organizations_select_member" ON organizations
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM organization_members
      WHERE organization_id = organizations.id
      AND profile_id = auth.clerk_user_id())
  );
```

### Request Fingerprinting

Requests are fingerprinted using:
- Client IP address
- User-Agent header
- Tenant ID

This enables detection of suspicious activity like token theft.

---

## Configuration

### Required Environment Variables

```bash
# Application
ENVIRONMENT=production
DEBUG=false

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...

# Clerk
CLERK_SECRET_KEY=sk_live_...
CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_JWT_ISSUER=https://your-clerk.clerk.accounts.dev
CLERK_JWKS_URL=https://your-clerk.clerk.accounts.dev/.well-known/jwks.json

# N8N
N8N_BASE_URL=https://your-n8n-instance.com
N8N_INTERNAL_AUTH_SECRET=<64+ character secret>
N8N_API_KEY=<n8n api key>  # Optional: enables dynamic credential injection
```

### Optional Configuration

```bash
# Rate Limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
REDIS_URL=redis://localhost:6379/0

# Security
ENABLE_FINGERPRINTING=true
CORS_ORIGINS=https://your-app.com,https://localhost:3000

# Development Only
DEV_SKIP_AUTH=false
DEV_DEFAULT_USER_ID=dev_user_001
DEV_DEFAULT_ORG_ID=dev_org_001
```

---

## Deployment

### Docker Compose

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f gateway
```

### Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DEBUG=false`
- [ ] Set `DEV_SKIP_AUTH=false`
- [ ] Use 64+ character `N8N_INTERNAL_AUTH_SECRET`
- [ ] Configure CORS origins
- [ ] Enable rate limiting with Redis
- [ ] Set up monitoring/alerting
- [ ] Configure SSL/TLS termination

---

## Development

### Local Setup

```bash
# Clone repository
git clone <repo-url>
cd n8n-gateway

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env
# Edit .env with your values

# Run development server
python -m app.main
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html

# Run specific test file
pytest tests/test_security.py -v
```

### Code Style

```bash
# Format code
ruff format .

# Check linting
ruff check .

# Type checking
mypy app/
```

---

## Troubleshooting

### Common Issues

**1. "JWT verification failed"**
- Check `CLERK_SECRET_KEY` is correct
- Verify `CLERK_JWKS_URL` is accessible
- Ensure token hasn't expired

**2. "Organization not found"**
- Verify the organization exists in database
- Check user is a member of the organization
- Ensure `org_id` claim is in JWT (or use X-Tenant-ID header)

**3. "Insufficient credits"**
- Check organization's credit balance
- Verify workflow's `credits_per_execution` setting
- Top up credits via billing

**4. "n8n webhook error"**
- Verify `N8N_BASE_URL` is correct
- Check n8n workflow is activated
- Verify webhook path matches configuration

---

## Support

For issues and feature requests, please open a GitHub issue.
