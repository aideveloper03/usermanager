# Code Structure

Detailed overview of the N8N Orchestration Gateway codebase architecture.

## Project Layout

```
n8n-orchestration-gateway/
├── app/                        # FastAPI Backend Application
│   ├── __init__.py
│   ├── main.py                 # Application entry point
│   ├── api/
│   │   └── v1/
│   │       ├── __init__.py     # API router aggregation
│   │       └── endpoints/
│   │           ├── execute.py      # Workflow execution
│   │           ├── health.py       # Health checks
│   │           ├── internal.py     # n8n callbacks
│   │           ├── organizations.py # Org management
│   │           └── workflows.py    # Workflow management
│   ├── core/
│   │   ├── config.py           # Pydantic settings
│   │   ├── rate_limiter.py     # Redis rate limiting
│   │   └── security.py         # HMAC, JWT, sanitization
│   ├── middleware/
│   │   └── auth_middleware.py  # Auth, fingerprinting
│   ├── models/
│   │   └── schemas.py          # Pydantic models
│   └── services/
│       ├── database.py         # Supabase operations
│       └── n8n_client.py       # n8n HTTP client
├── frontend/                   # Next.js Frontend
│   ├── src/
│   │   ├── app/               # Next.js App Router
│   │   │   ├── layout.tsx     # Root layout with Clerk
│   │   │   ├── page.tsx       # Landing page
│   │   │   ├── dashboard/     # Protected dashboard
│   │   │   ├── sign-in/       # Clerk sign-in
│   │   │   └── sign-up/       # Clerk sign-up
│   │   ├── components/        # React components
│   │   └── middleware.ts      # Clerk middleware
│   ├── package.json
│   └── Dockerfile
├── supabase/
│   └── migrations/
│       ├── 01_initial_schema.sql
│       └── 02_clerk_native_integration.sql
├── tests/
│   ├── conftest.py            # Test fixtures
│   ├── local_test.py          # E2E test runner
│   ├── test_health.py
│   ├── test_schemas.py
│   └── test_security.py
├── docs/                       # Documentation
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── pyproject.toml
```

## Backend Architecture

### Entry Point (`app/main.py`)

```python
# Application factory pattern
def create_application() -> FastAPI:
    app = FastAPI(...)
    
    # Configure CORS
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, ...)
    
    # Setup auth/security middleware
    setup_middleware(app)
    
    # Setup rate limiting
    setup_rate_limiting(app)
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    return app

# Lifespan for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify connections
    yield
    # Shutdown: cleanup
```

### Configuration (`app/core/config.py`)

Uses Pydantic Settings for type-safe configuration:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
    )
    
    # Application
    app_name: str = "N8N Gateway"
    environment: str = "production"
    
    # Supabase
    supabase_url: str
    supabase_service_role_key: str
    
    # Clerk
    clerk_jwks_url: str
    
    # n8n
    n8n_base_url: str
    n8n_internal_auth_secret: str
    
    # Custom parsing for lists
    cors_origins: CommaSeparatedList = []
```

### Security (`app/core/security.py`)

Multiple security components:

```python
# HMAC Validation
class HMACValidator:
    def compute_signature(self, secret, timestamp, body) -> str
    def validate_signature(self, ...) -> bool

# JWT Verification
class ClerkJWTVerifier:
    async def verify_token(self, token) -> dict
    def get_user_id_from_claims(self, claims) -> str

# Input Sanitization
class Sanitizer:
    def sanitize_string(self, value) -> str
    def sanitize_dict(self, data) -> dict

# Fingerprinting
class RequestFingerprinter:
    def generate_fingerprint(self, ip, ua, tenant) -> str
```

### Middleware (`app/middleware/auth_middleware.py`)

Request processing pipeline:

```python
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # 1. Generate request ID
        # 2. Check dev bypass mode
        # 3. Extract auth token (JWT or API key)
        # 4. Validate and store user context
        # 5. Call next handler

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # 1. Validate HMAC signature
        # 2. Generate fingerprint
        # 3. Log request
```

Developer Bypass:

```python
class DevBypassAuth:
    @classmethod
    def is_enabled(cls) -> bool:
        return settings.dev_skip_auth
    
    @classmethod
    def get_mock_claims(cls, request) -> dict:
        return {
            "sub": request.headers.get("X-Dev-User-ID"),
            "org_id": request.headers.get("X-Dev-Org-ID"),
        }
```

### Database Service (`app/services/database.py`)

Supabase operations with proper error handling:

```python
class DatabaseService:
    def __init__(self, url, key):
        self._client = create_client(url, key)
    
    # Profile operations
    async def get_profile(self, profile_id: str) -> dict
    async def upsert_profile(self, data: dict) -> dict
    
    # Organization operations
    async def get_organization(self, org_id: UUID) -> dict
    async def create_organization(self, name, owner_id, ...) -> dict
    
    # Workflow operations
    async def get_workflow_by_org(self, org_id, workflow_id) -> dict
    
    # Credit operations (atomic via RPC)
    async def deduct_credits(self, org_id, amount, ...) -> dict
    async def refund_credits(self, usage_log_id) -> dict
    
    # Vault operations
    async def get_tenant_credentials(self, org_id) -> dict
    async def get_credentials_with_lock(self, org_id) -> dict
```

### n8n Client (`app/services/n8n_client.py`)

HTTP client for n8n communication:

```python
class N8NClient:
    def __init__(self, base_url, internal_auth_secret, api_key=None):
        self.credential_injector = CredentialInjector(...) if api_key else None
    
    async def execute_webhook(
        self,
        webhook_path: str,
        data: dict,
        tenant_credentials: dict | None,
        credential_mappings: dict | None,
        use_dynamic_injection: bool = False,
    ) -> dict:
        # 1. Optionally inject credentials via n8n API
        # 2. Construct payload
        # 3. Send POST to webhook
        # 4. Handle response/errors

class CredentialInjector:
    async def update_credential(self, cred_id, data) -> bool
    async def inject_credentials(self, creds, mappings) -> dict
```

### API Endpoints

#### Execute (`app/api/v1/endpoints/execute.py`)

Main workflow execution flow:

```python
@router.post("")
async def execute_workflow(request, execute_request, db, n8n):
    # 1. Determine auth method (JWT/API key/dev bypass)
    # 2. Get organization context
    # 3. Verify org is active
    # 4. Get workflow configuration
    # 5. Deduct credits atomically
    # 6. Retrieve tenant credentials
    # 7. Execute n8n webhook
    # 8. Update usage status
    # 9. Return response
```

#### Health (`app/api/v1/endpoints/health.py`)

```python
@router.get("")
async def health():
    return {
        "status": "healthy",
        "version": settings.app_version,
        "checks": {
            "database": await check_db(),
            "n8n": await check_n8n(),
        }
    }
```

## Frontend Architecture

### App Router Structure

```
src/app/
├── layout.tsx          # Root layout with ClerkProvider
├── page.tsx            # Landing page
├── dashboard/
│   └── page.tsx        # Protected dashboard
├── sign-in/
│   └── [[...sign-in]]/
│       └── page.tsx    # Clerk SignIn component
└── sign-up/
    └── [[...sign-up]]/
        └── page.tsx    # Clerk SignUp component
```

### Key Components

```tsx
// Layout with Clerk
export default function RootLayout({ children }) {
  return (
    <ClerkProvider>
      <html>
        <body>{children}</body>
      </html>
    </ClerkProvider>
  );
}

// Dashboard with API integration
export default function DashboardPage() {
  const { getToken } = useAuth();
  
  async function executeWorkflow(workflowId) {
    const token = await getToken();
    const response = await fetch(`${GATEWAY_URL}/api/v1/execute`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ workflow_id: workflowId, data: {} }),
    });
    return response.json();
  }
}
```

### Middleware

```typescript
// src/middleware.ts
export default clerkMiddleware((auth, req) => {
  if (!isPublicRoute(req)) {
    auth().protect();
  }
});
```

## Data Flow

### Workflow Execution Flow

```
1. Client sends POST /api/v1/execute with JWT
   │
2. AuthMiddleware validates JWT
   │
3. SecurityMiddleware generates fingerprint
   │
4. execute_workflow endpoint:
   │
   ├─► Validate organization
   ├─► Check credits (atomic)
   ├─► Get credentials from Vault
   ├─► Execute n8n webhook
   └─► Update usage log
   │
5. Return ExecuteResponse to client
```

### Credit Deduction Flow

```sql
-- Atomic credit deduction (fn_deduct_credits)
1. Lock organization row (FOR UPDATE)
2. Check credits >= amount
3. Deduct credits
4. Create usage_log entry
5. Return success + remaining credits
```

## Testing

### Unit Tests

```python
# tests/conftest.py
@pytest.fixture
def mock_db_service():
    mock = MagicMock(spec=DatabaseService)
    mock.get_workflow_by_org = AsyncMock(return_value={...})
    mock.deduct_credits = AsyncMock(return_value={"success": True})
    return mock
```

### E2E Tests

```python
# tests/local_test.py
class LocalTestRunner:
    async def test_execute_workflow(self):
        status, data = await self._make_request(
            "POST", "/api/v1/execute",
            json_data={"workflow_id": "...", "data": {}}
        )
        assert status < 500
```

## Dependency Injection

Services are injected via FastAPI dependencies:

```python
# Singleton pattern
_db_service: DatabaseService | None = None

def get_db_service() -> DatabaseService:
    global _db_service
    if _db_service is None:
        _db_service = DatabaseService(
            settings.supabase_url,
            settings.supabase_service_role_key
        )
    return _db_service

# Usage in endpoints
@router.post("")
async def execute(
    db: DatabaseService = Depends(get_db_service),
    n8n: N8NClient = Depends(get_n8n_client),
):
    ...
```

## Error Handling

Structured error responses:

```python
class ErrorResponse(BaseModel):
    error: str
    message: str
    request_id: str | None

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("unhandled_exception", error=str(exc))
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            message="An unexpected error occurred",
            request_id=request.state.request_id
        ).model_dump()
    )
```
