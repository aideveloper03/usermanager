# N8N Orchestration Gateway Architecture

## Overview

The N8N Orchestration Gateway is a production-ready, multi-tenant API wrapper for private n8n instances. It provides secure authentication, credit-based billing, and tenant credential isolation using Clerk for authentication and Supabase for data persistence with Row-Level Security (RLS).

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Applications                              │
│                   (Web Apps, Mobile Apps, API Consumers)                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        │ HTTPS
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Gateway (Python)                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Auth        │  │ Security    │  │ Rate        │  │ Request             │ │
│  │ Middleware  │  │ Middleware  │  │ Limiter     │  │ Fingerprinting      │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                     │            │
│         └────────────────┴────────────────┴─────────────────────┘            │
│                                        │                                      │
│  ┌─────────────────────────────────────┴───────────────────────────────────┐ │
│  │                          API Endpoints (v1)                              │ │
│  │  /execute  │  /workflows  │  /organizations  │  /health  │  /internal   │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
          │                                           │
          │ Clerk JWT                                 │ Service Role
          ▼                                           ▼
┌─────────────────────┐                    ┌─────────────────────┐
│   Clerk (Auth)      │                    │  Supabase (DB)      │
│  ┌───────────────┐  │                    │  ┌───────────────┐  │
│  │ JWT Issuance  │  │                    │  │ PostgreSQL    │  │
│  │ JWKS Endpoint │◄─┼─Validate JWT──────►│  │ + RLS         │  │
│  │ User Mgmt     │  │                    │  │ + Vault       │  │
│  └───────────────┘  │                    │  └───────────────┘  │
└─────────────────────┘                    └─────────────────────┘
                                                      │
                                                      │ Credentials
                                                      ▼
                                           ┌─────────────────────┐
                                           │     N8N Instance    │
                                           │  ┌───────────────┐  │
                                           │  │ Webhooks      │  │
                                           │  │ Workflows     │  │
                                           │  │ Credentials   │  │
                                           │  └───────────────┘  │
                                           └─────────────────────┘
```

## Authentication Architecture

### Clerk Native Supabase Integration

The gateway uses Clerk's native Supabase integration, which provides:

1. **Single JWT for Both Systems**: The Clerk JWT is validated by both the Python gateway AND Supabase
2. **RLS Enforcement**: Supabase RLS policies use `auth.jwt()->>'sub'` to identify the Clerk user
3. **No Custom JWT Templates**: Uses Clerk's standard JWT format directly

### Authentication Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        JWT Authentication Flow                              │
└────────────────────────────────────────────────────────────────────────────┘

1. Client Request
   ┌──────────┐                          ┌──────────────┐
   │  Client  │──── Bearer Token ───────►│   Gateway    │
   └──────────┘                          └──────────────┘
                                                │
2. JWT Validation (Gateway)                     │
   ┌──────────────────────────────────────────┐ │
   │ ClerkJWTVerifier.verify_token()          │◄┘
   │   - Fetch JWKS from Clerk                │
   │   - Validate signature                    │
   │   - Check expiration                      │
   │   - Extract claims (sub, org_id, etc)    │
   └──────────────────────────────────────────┘
                                                │
3. Store JWT in Request State                   │
   ┌──────────────────────────────────────────┐ │
   │ request.state.clerk_jwt = token          │◄┘
   │ request.state.user_id = claims['sub']    │
   │ request.state.org_id = claims['org_id']  │
   └──────────────────────────────────────────┘
                                                │
4. Database Access with RLS                     │
   ┌──────────────────────────────────────────┐ │
   │ AuthenticatedDatabaseService(clerk_jwt)  │◄┘
   │   - Creates Supabase client with JWT     │
   │   - JWT passed in Authorization header   │
   │   - Supabase validates JWT via JWKS      │
   │   - RLS policies enforce data access     │
   └──────────────────────────────────────────┘
```

### Two Database Client Modes

```python
# 1. Service Role Client - Bypasses RLS (for admin operations)
db = get_db_service()  # Singleton, uses service role key

# 2. Authenticated Client - Enforces RLS (for user operations)
db = get_authenticated_db_service(clerk_jwt, user_id)  # Per-request
```

**When to use each:**

| Client Type | Use Case | RLS | Example Operations |
|-------------|----------|-----|-------------------|
| Service Role | Webhooks, Background Jobs, Admin | Bypassed | Credit deduction, Usage logging |
| Authenticated | User-initiated requests | Enforced | Reading own profile, org data |

## Database Architecture

### Schema Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Supabase PostgreSQL                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐     ┌─────────────────────┐     ┌─────────────────────┐    │
│  │  profiles   │     │   organizations     │     │    workflows        │    │
│  │─────────────│     │─────────────────────│     │─────────────────────│    │
│  │ id (PK)     │◄────│ owner_id (FK)       │     │ organization_id(FK) │────┤
│  │ email       │     │ tenant_id           │◄────│ n8n_workflow_id     │    │
│  │ name        │     │ api_key_hash        │     │ n8n_webhook_path    │    │
│  │ metadata    │     │ credits             │     │ credits_per_exec    │    │
│  └─────────────┘     │ plan_type           │     └─────────────────────┘    │
│         │            └─────────────────────┘                                 │
│         │                     │                                              │
│         │            ┌────────┴────────┐                                     │
│         ▼            ▼                 ▼                                     │
│  ┌─────────────────────────┐  ┌─────────────────────┐                       │
│  │ organization_members    │  │   usage_logs        │                       │
│  │─────────────────────────│  │─────────────────────│                       │
│  │ organization_id (FK)    │  │ organization_id(FK) │                       │
│  │ profile_id (FK)         │  │ workflow_id (FK)    │                       │
│  │ role                    │  │ credits_used        │                       │
│  └─────────────────────────┘  │ status              │                       │
│                               │ execution_time_ms   │                       │
│                               └─────────────────────┘                       │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          vault.secrets                               │    │
│  │  (Encrypted tenant credentials - accessed via RPC functions)        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Row-Level Security (RLS)

RLS policies enforce data isolation using Clerk JWT claims:

```sql
-- Example: Users can only read their own profile
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (id = (auth.jwt()->>'sub'));

-- Example: Members can read their organization's workflows
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

## Credential Injection Architecture

### Static Identity / Dynamic Data Pattern

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Credential Injection Flow                                 │
└─────────────────────────────────────────────────────────────────────────────┘

1. Request Received
   Gateway receives workflow execution request

2. Acquire Advisory Lock
   ┌────────────────────────────────────────┐
   │ fn_acquire_credential_lock(org_id)     │  Prevents concurrent credential
   │ Returns: lock acquired (boolean)       │  updates from interfering
   └────────────────────────────────────────┘

3. Retrieve Credentials from Vault
   ┌────────────────────────────────────────┐
   │ private.get_tenant_credentials(org_id) │  Decrypts credentials from
   │ Returns: JSONB with service secrets    │  Supabase Vault
   └────────────────────────────────────────┘

4. Inject into N8N (Dynamic Mode)
   ┌────────────────────────────────────────┐
   │ PATCH /api/v1/credentials/{id}         │  Updates n8n base credential
   │ Body: { data: tenant_secrets }         │  with tenant-specific data
   └────────────────────────────────────────┘

5. Execute Workflow
   ┌────────────────────────────────────────┐
   │ POST /webhook/{webhook_path}           │  Triggers n8n workflow with
   │ Uses updated credentials               │  injected credentials
   └────────────────────────────────────────┘

6. Release Lock (on transaction commit)
   Advisory lock is automatically released when the database
   transaction commits or rolls back.
```

### Credential Storage in Vault

```sql
-- Store credentials (encrypted at rest)
SELECT private.store_tenant_credentials(
    p_org_id => 'org-uuid',
    p_credentials => '{
        "openai": {"api_key": "sk-..."},
        "slack": {"access_token": "xoxb-..."}
    }'::JSONB
);

-- Retrieve credentials (decrypted)
SELECT private.get_tenant_credentials('org-uuid');
```

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Security Layers                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Layer 1: Transport Security                                                 │
│  ├─ HTTPS/TLS encryption                                                     │
│  └─ HSTS headers                                                             │
│                                                                              │
│  Layer 2: Authentication                                                     │
│  ├─ Clerk JWT validation (JWKS-based)                                        │
│  ├─ API key validation (SHA-256 hash comparison)                             │
│  └─ HMAC signature validation (anti-replay)                                  │
│                                                                              │
│  Layer 3: Authorization                                                      │
│  ├─ RLS policies in PostgreSQL                                               │
│  ├─ Organization membership verification                                     │
│  └─ Role-based access control                                                │
│                                                                              │
│  Layer 4: Input Validation                                                   │
│  ├─ Pydantic schema validation                                               │
│  ├─ HTML/XSS sanitization (bleach)                                           │
│  └─ Request size limits                                                      │
│                                                                              │
│  Layer 5: Rate Limiting                                                      │
│  ├─ Redis-backed sliding window                                              │
│  └─ Per-tenant rate limits                                                   │
│                                                                              │
│  Layer 6: Monitoring                                                         │
│  ├─ Request fingerprinting                                                   │
│  ├─ Security event logging                                                   │
│  └─ Anomaly detection                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JWT Validation Flow

```python
# 1. Middleware extracts and validates JWT
token = request.headers.get("Authorization").split(" ")[1]
claims = await jwt_verifier.verify_token(token)

# 2. Store for downstream use
request.state.clerk_jwt = token
request.state.user_id = claims["sub"]

# 3. Create authenticated DB client
db = get_authenticated_db_service(token, claims["sub"])

# 4. Supabase validates JWT again via its third-party auth config
# and enforces RLS based on auth.jwt()->>'sub'
```

## Request Flow

### Workflow Execution Request

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        POST /api/v1/execute                                  │
└──────────────────────────────────────────────────────────────────────────────┘

1. ─────────────────────────────────────────────────────────────────────────────
   │ AuthMiddleware: Validate JWT/API Key
   │ ├─ Extract Bearer token
   │ ├─ Validate against Clerk JWKS
   │ └─ Store claims in request.state
   └───────────────────────────────────────────────────────────────────────────►

2. ─────────────────────────────────────────────────────────────────────────────
   │ SecurityMiddleware: Fingerprint & Log
   │ ├─ Extract IP, User-Agent
   │ ├─ Generate fingerprint hash
   │ └─ Start request timer
   └───────────────────────────────────────────────────────────────────────────►

3. ─────────────────────────────────────────────────────────────────────────────
   │ Execute Endpoint: Main Logic
   │ ├─ Verify organization (active, valid)
   │ ├─ Verify workflow exists and is active
   │ ├─ Deduct credits atomically (RPC)
   │ ├─ Retrieve credentials from Vault
   │ ├─ Execute n8n webhook
   │ └─ Update usage log with result
   └───────────────────────────────────────────────────────────────────────────►

4. ─────────────────────────────────────────────────────────────────────────────
   │ Response: ExecuteResponse
   │ {
   │   "success": true,
   │   "execution_id": "uuid",
   │   "status": "completed",
   │   "credits_used": 1,
   │   "execution_time_ms": 1234
   │ }
   └───────────────────────────────────────────────────────────────────────────►
```

## Configuration

### Environment Variables

```bash
# Supabase
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_ANON_KEY=eyJhbG...           # For authenticated clients
SUPABASE_SERVICE_ROLE_KEY=eyJhbG...   # For admin operations

# Clerk
CLERK_JWT_ISSUER=https://xxx.clerk.accounts.dev
CLERK_JWKS_URL=https://xxx.clerk.accounts.dev/.well-known/jwks.json
CLERK_SECRET_KEY=sk_test_xxx

# N8N
N8N_BASE_URL=https://n8n.example.com
N8N_INTERNAL_AUTH_SECRET=xxx          # 64+ character secret
N8N_API_KEY=xxx                       # For dynamic credential injection
N8N_USE_DYNAMIC_CREDENTIALS=true
```

### Supabase Third-Party Auth Setup

1. **Clerk Dashboard**: Integrations → Supabase → Copy issuer URL
2. **Supabase Dashboard**: Authentication → Providers → Third-party Auth
3. Configure:
   - Auth Provider: Clerk
   - JWKS URL: `https://YOUR_CLERK_FRONTEND_API/.well-known/jwks.json`
   - JWT Issuer: Your Clerk issuer URL

## Deployment

### Production Checklist

- [ ] HTTPS/TLS configured
- [ ] Environment is set to `production`
- [ ] `DEV_SKIP_AUTH=false`
- [ ] `N8N_INTERNAL_AUTH_SECRET` is 64+ characters
- [ ] Rate limiting enabled
- [ ] HMAC validation enabled
- [ ] Supabase RLS policies applied
- [ ] Clerk third-party auth configured in Supabase
- [ ] Redis configured for rate limiting
- [ ] Monitoring/alerting set up

### Scaling Considerations

- **Stateless Design**: Gateway is stateless, horizontally scalable
- **Connection Pooling**: Supabase handles connection pooling via PgBouncer
- **Rate Limiting**: Redis-backed for distributed rate limiting
- **Caching**: JWKS is cached with configurable TTL (default 1 hour)
