# N8N Orchestration Gateway

A production-ready, hardened B2B API wrapper that acts as a secure, authenticated proxy for private n8n instances.

## Overview

This gateway provides multi-tenant workflow orchestration with enterprise-grade security features:

- **Multi-tenant Architecture** - Organizations with isolated API keys and credentials
- **Credit-based Billing** - Pay-per-execution model with atomic credit deduction
- **Secure Authentication** - Clerk JWT validation and API key authentication
- **Anti-Hijacking Protection** - HMAC signature validation with timestamp checking
- **Request Fingerprinting** - IP + User-Agent + Tenant-ID based anomaly detection
- **Rate Limiting** - Redis-backed sliding window rate limiting
- **Input Sanitization** - Automatic XSS payload stripping with bleach
- **Credential Injection** - Secure tenant credential storage in Supabase Vault

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Client Request                             │
│              (JWT Token or API Key + HMAC Signature)                │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    N8N Orchestration Gateway                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   Auth      │  │  Security   │  │    Rate     │  │  Request   │ │
│  │ Middleware  │→ │ Middleware  │→ │  Limiting   │→ │ Processing │ │
│  │ (JWT/API)   │  │(HMAC/FP)    │  │  (Redis)    │  │            │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────┬──────┘ │
│                                                            │        │
│  ┌─────────────────────────────────────────────────────────┘        │
│  │                                                                   │
│  ▼                                                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ Credit Check    │→ │ Vault Lookup    │→ │ N8N Client      │     │
│  │ (fn_deduct)     │  │ (Credentials)   │  │ (Webhook POST)  │     │
│  └─────────────────┘  └─────────────────┘  └────────┬────────┘     │
│                                                       │              │
└───────────────────────────────────────────────────────┼──────────────┘
                                                        │
                                                        ▼
                              ┌─────────────────────────────────────────┐
                              │              n8n Instance               │
                              │  ┌─────────────────────────────────┐   │
                              │  │    Workflow Webhook Execution   │   │
                              │  │  (with injected credentials)    │   │
                              │  └─────────────────────────────────┘   │
                              └─────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- Redis (for rate limiting)
- Supabase account
- Clerk account
- n8n instance

### Installation

1. **Clone and setup:**

```bash
git clone <repository>
cd n8n-orchestration-gateway
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

2. **Configure environment:**

```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Setup Supabase database:**

```bash
# Apply the migration to your Supabase project
# Copy contents of supabase/migrations/01_initial_schema.sql
# to Supabase SQL Editor and run
```

4. **Run the application:**

```bash
# Development
uvicorn app.main:app --reload --port 8000

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Docker

```bash
# Development with docker-compose
docker-compose up -d

# Production build
docker build -t n8n-gateway .
docker run -p 8000:8000 --env-file .env n8n-gateway
```

## API Reference

### Authentication

The API supports two authentication methods:

#### 1. Clerk JWT (Recommended)

```bash
curl -X POST https://gateway.example.com/api/v1/execute \
  -H "Authorization: Bearer <clerk-jwt-token>" \
  -H "X-Tenant-ID: your-tenant-id" \
  -H "Content-Type: application/json" \
  -d '{"workflow_id": "uuid", "data": {...}}'
```

#### 2. API Key with HMAC

```bash
TIMESTAMP=$(date +%s)
BODY='{"workflow_id": "uuid", "data": {...}}'
SIGNATURE=$(echo -n "${TIMESTAMP}${BODY}" | openssl dgst -sha256 -hmac "your-client-secret" | cut -d' ' -f2)

curl -X POST https://gateway.example.com/api/v1/execute \
  -H "X-API-Key: gw_live_xxxxx" \
  -H "X-Tenant-ID: your-tenant-id" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Signature: ${SIGNATURE}" \
  -H "Content-Type: application/json" \
  -d "${BODY}"
```

### Endpoints

#### Execute Workflow

```http
POST /api/v1/execute
```

Execute an n8n workflow through the gateway.

**Request Body:**

```json
{
  "workflow_id": "uuid-of-registered-workflow",
  "data": {
    "your": "input data"
  },
  "callback_url": "https://your-app.com/callback",
  "timeout_override": 300,
  "metadata": {
    "source": "api"
  }
}
```

**Response:**

```json
{
  "success": true,
  "execution_id": "usage-log-uuid",
  "status": "completed",
  "data": {
    "workflow": "response"
  },
  "credits_used": 1,
  "credits_remaining": 999,
  "execution_time_ms": 150
}
```

#### Organizations

```http
POST   /api/v1/organizations          # Create organization
GET    /api/v1/organizations          # List my organizations
GET    /api/v1/organizations/{id}     # Get organization
PATCH  /api/v1/organizations/{id}     # Update organization
GET    /api/v1/organizations/{id}/usage  # Get usage logs
POST   /api/v1/organizations/{id}/credentials  # Store tenant credentials
DELETE /api/v1/organizations/{id}/credentials  # Delete credentials
```

#### Workflows

```http
POST   /api/v1/workflows              # Register workflow
GET    /api/v1/workflows              # List workflows
GET    /api/v1/workflows/{id}         # Get workflow
PATCH  /api/v1/workflows/{id}         # Update workflow
POST   /api/v1/workflows/{id}/activate     # Activate workflow
POST   /api/v1/workflows/{id}/deactivate   # Deactivate workflow
```

#### Health

```http
GET /api/v1/health        # Basic health check
GET /api/v1/health/ready  # Readiness check (verifies dependencies)
GET /api/v1/health/live   # Liveness probe
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SUPABASE_URL` | Supabase project URL | Yes | - |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | Yes | - |
| `CLERK_SECRET_KEY` | Clerk secret key | Yes | - |
| `CLERK_JWKS_URL` | Clerk JWKS URL | Yes | - |
| `N8N_BASE_URL` | n8n instance URL | Yes | - |
| `N8N_INTERNAL_AUTH_SECRET` | Secret for n8n internal auth | Yes | - |
| `REDIS_URL` | Redis connection URL | No | `redis://localhost:6379/0` |
| `RATE_LIMIT_REQUESTS` | Requests per period | No | 100 |
| `RATE_LIMIT_PERIOD` | Period in seconds | No | 60 |
| `HMAC_TIMESTAMP_TOLERANCE` | HMAC timestamp tolerance (seconds) | No | 300 |
| `ENABLE_RATE_LIMITING` | Enable/disable rate limiting | No | true |
| `ENABLE_HMAC_VALIDATION` | Enable/disable HMAC validation | No | true |
| `ENABLE_FINGERPRINTING` | Enable/disable fingerprinting | No | true |

See `.env.example` for a complete list of configuration options.

## Security Features

### HMAC Signature Validation

All API key requests are validated using HMAC-SHA256:

```
signature = HMAC-SHA256(client_secret, timestamp + request_body)
```

- Requests older than 300 seconds (configurable) are rejected
- Constant-time comparison prevents timing attacks

### Request Fingerprinting

Each request generates a fingerprint from:
- Client IP address
- User-Agent header
- Tenant ID

Fingerprint changes trigger security alerts for investigation.

### Input Sanitization

All string inputs are sanitized using `bleach` to prevent:
- XSS attacks
- HTML injection
- Script injection

### Rate Limiting

Sliding window rate limiting with Redis:
- Per-tenant limits for authenticated requests
- Per-IP limits for fallback
- Custom limits per endpoint

## n8n Setup

### Webhook Configuration

1. Create a Webhook trigger node in n8n
2. Set **Response Mode** to "Last Node" or "When Last Node Finishes"
3. Add header authentication checking for `X-N8N-Internal-Auth`

### Error Workflow

Create a global error workflow that:
1. Catches workflow errors
2. POSTs to `/api/v1/internal/log-error` with:
   - X-N8N-Internal-Auth header
   - Error details in body

See [N8N Setup Guide](docs/N8N_SETUP.md) for detailed instructions.

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=app --cov-report=html
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

## Deployment

### Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DEBUG=false`
- [ ] Use HTTPS for all URLs
- [ ] Configure proper CORS origins
- [ ] Set strong `N8N_INTERNAL_AUTH_SECRET` (64+ characters)
- [ ] Enable rate limiting with Redis
- [ ] Configure trusted proxies for accurate IP detection
- [ ] Set up monitoring and alerting
- [ ] Enable structured JSON logging

### Kubernetes

Example deployment available in `k8s/` directory (if applicable).

### Monitoring

The gateway exposes:
- Health endpoints for probes
- Structured logging (JSON format)
- Security event logging

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
