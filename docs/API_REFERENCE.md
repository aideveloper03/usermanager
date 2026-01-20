# API Reference

Complete API documentation for the N8N Orchestration Gateway.

## Base URL

```
Production: https://api.your-domain.com/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

### JWT Authentication (Recommended)

Include Clerk JWT token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### API Key Authentication

Include API key and HMAC signature:

```http
X-API-Key: gw_live_xxxxxxxxxxxxx
X-Tenant-ID: your-tenant-id
X-Timestamp: 1700000000
X-Signature: hmac-sha256-signature
```

**Signature Computation:**

```python
import hmac
import hashlib
import time
import json

timestamp = str(int(time.time()))
body = json.dumps(request_body)
message = timestamp + body
signature = hmac.new(
    client_secret.encode(),
    message.encode(),
    hashlib.sha256
).hexdigest()
```

## Response Format

### Success Response

```json
{
  "success": true,
  "data": { ... },
  "request_id": "uuid"
}
```

### Error Response

```json
{
  "error": "error_code",
  "message": "Human-readable message",
  "details": { ... },
  "request_id": "uuid"
}
```

## Rate Limiting

Default: 100 requests per 60 seconds per tenant.

Response headers:
- `X-RateLimit-Limit`: Maximum requests
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Seconds until reset
- `Retry-After`: Seconds to wait (on 429)

---

## Endpoints

### Execute Workflow

Execute an n8n workflow through the gateway.

```http
POST /execute
```

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes* | Bearer token (JWT auth) |
| `X-API-Key` | Yes* | API key (API key auth) |
| `X-Tenant-ID` | Conditional | Required for API key auth |
| `X-Timestamp` | Conditional | Required for API key auth |
| `X-Signature` | Conditional | Required for API key auth |

*One of JWT or API key is required

**Request Body:**

```json
{
  "workflow_id": "uuid",
  "data": {
    "your": "input data"
  },
  "callback_url": "https://optional-callback.com",
  "timeout_override": 300,
  "metadata": {
    "source": "api"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `workflow_id` | UUID | Yes | Registered workflow UUID |
| `data` | object | No | Input data for the workflow |
| `callback_url` | URL | No | Webhook for async results |
| `timeout_override` | integer | No | Custom timeout (10-600s) |
| `metadata` | object | No | Additional tracking data |

**Response (200 OK):**

```json
{
  "success": true,
  "execution_id": "uuid",
  "status": "completed",
  "data": {
    "workflow": "response"
  },
  "credits_used": 1,
  "credits_remaining": 999,
  "execution_time_ms": 150
}
```

**Error Responses:**

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | bad_request | Invalid request body |
| 401 | unauthorized | Authentication failed |
| 402 | insufficient_credits | Not enough credits |
| 403 | forbidden | HMAC validation failed |
| 404 | not_found | Workflow not found |
| 429 | rate_limit_exceeded | Too many requests |
| 502 | n8n_error | n8n returned an error |
| 504 | gateway_timeout | n8n request timed out |

---

### Execute Workflow (Streaming)

Execute workflow and stream the response.

```http
POST /execute/stream
```

Same request format as `/execute`. Response is streamed as chunks.

---

## Organizations

### Create Organization

Create a new organization with API credentials.

```http
POST /organizations
```

**Request Body:**

```json
{
  "name": "My Organization",
  "tenant_id": "my-org-tenant",
  "plan_type": "starter"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Organization name |
| `tenant_id` | string | Yes | Unique tenant ID (lowercase, alphanumeric, hyphens) |
| `plan_type` | string | No | free, starter, professional, enterprise |

**Response (201 Created):**

```json
{
  "id": "uuid",
  "name": "My Organization",
  "tenant_id": "my-org-tenant",
  "api_key_prefix": "gw_live_xxxx",
  "api_key": "gw_live_full_key_only_shown_once",
  "client_secret": "secret_only_shown_once",
  "credits": 1000,
  "plan_type": "starter",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

⚠️ **Important**: `api_key` and `client_secret` are only returned on creation.

---

### List Organizations

Get all organizations for the authenticated user.

```http
GET /organizations
```

**Response (200 OK):**

```json
[
  {
    "id": "uuid",
    "name": "My Organization",
    "tenant_id": "my-org-tenant",
    "api_key_prefix": "gw_live_xxxx",
    "credits": 950,
    "plan_type": "starter",
    "is_active": true,
    "role": "owner",
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

---

### Get Organization

Get organization details by ID.

```http
GET /organizations/{org_id}
```

**Parameters:**

| Name | In | Type | Required |
|------|-----|------|----------|
| `org_id` | path | UUID | Yes |

---

### Update Organization

Update organization settings.

```http
PATCH /organizations/{org_id}
```

**Request Body:**

```json
{
  "name": "Updated Name",
  "settings": {
    "webhook_url": "https://callback.com"
  }
}
```

---

### Get Usage Logs

Get paginated usage logs for an organization.

```http
GET /organizations/{org_id}/usage
```

**Query Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page (max 100) |

**Response (200 OK):**

```json
{
  "items": [
    {
      "id": "uuid",
      "workflow_id": "uuid",
      "credits_used": 1,
      "status": "completed",
      "execution_time_ms": 150,
      "created_at": "2024-01-01T00:00:00Z",
      "completed_at": "2024-01-01T00:00:01Z"
    }
  ],
  "total": 100,
  "page": 1,
  "page_size": 20,
  "total_pages": 5
}
```

---

### Store Tenant Credentials

Store encrypted credentials for workflow injection.

```http
POST /organizations/{org_id}/credentials
```

**Request Body:**

```json
{
  "linkedin_api_key": "your-key",
  "openai_key": "sk-xxx",
  "custom_service": {
    "token": "abc",
    "url": "https://api.example.com"
  }
}
```

**Response (201 Created):**

```json
{
  "message": "Credentials stored successfully"
}
```

---

### Delete Tenant Credentials

Delete stored credentials.

```http
DELETE /organizations/{org_id}/credentials
```

**Response (204 No Content)**

---

## Workflows

### Create Workflow

Register an n8n workflow with the gateway.

```http
POST /workflows?org_id={uuid}
```

**Query Parameters:**

| Name | Type | Required |
|------|------|----------|
| `org_id` | UUID | Yes |

**Request Body:**

```json
{
  "name": "LinkedIn Summarizer",
  "description": "Summarizes LinkedIn profiles",
  "n8n_workflow_id": "wf_abc123",
  "n8n_webhook_path": "/webhook/linkedin-summarizer",
  "credits_per_execution": 2,
  "timeout_seconds": 300,
  "is_active": true,
  "settings": {
    "retry_on_failure": true,
    "max_retries": 3
  }
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Workflow name |
| `description` | string | No | null | Description |
| `n8n_workflow_id` | string | Yes | - | n8n workflow ID |
| `n8n_webhook_path` | string | Yes | - | Webhook path in n8n |
| `credits_per_execution` | integer | No | 1 | Credits per run |
| `timeout_seconds` | integer | No | 300 | Timeout (10-600s) |
| `is_active` | boolean | No | true | Whether active |
| `settings` | object | No | {} | Additional settings |

---

### List Workflows

Get all workflows for an organization.

```http
GET /workflows?org_id={uuid}&include_inactive=false
```

**Query Parameters:**

| Name | Type | Default |
|------|------|---------|
| `org_id` | UUID | Required |
| `include_inactive` | boolean | false |

---

### Get Workflow

Get workflow details.

```http
GET /workflows/{workflow_id}
```

---

### Update Workflow

Update workflow configuration.

```http
PATCH /workflows/{workflow_id}
```

**Request Body:**

```json
{
  "name": "Updated Name",
  "credits_per_execution": 3,
  "is_active": false
}
```

---

### Activate Workflow

Activate a workflow for execution.

```http
POST /workflows/{workflow_id}/activate
```

---

### Deactivate Workflow

Deactivate a workflow.

```http
POST /workflows/{workflow_id}/deactivate
```

---

## Health

### Basic Health Check

```http
GET /health
```

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "production",
  "timestamp": "2024-01-01T00:00:00Z",
  "checks": {}
}
```

---

### Readiness Check

Verifies all dependencies are available.

```http
GET /health/ready
```

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "production",
  "timestamp": "2024-01-01T00:00:00Z",
  "checks": {
    "supabase": true,
    "n8n": true,
    "redis": true
  }
}
```

---

### Liveness Check

Kubernetes liveness probe.

```http
GET /health/live
```

---

## Internal Endpoints

These endpoints are for n8n callbacks and require `X-N8N-Internal-Auth` header.

### Log Error from n8n

```http
POST /internal/log-error
```

**Headers:**

```http
X-N8N-Internal-Auth: your-internal-secret
```

**Request Body:**

```json
{
  "workflow_id": "n8n-workflow-id",
  "execution_id": "n8n-execution-id",
  "error_message": "Error description",
  "error_stack": "Stack trace...",
  "timestamp": "2024-01-01T00:00:00Z",
  "metadata": {}
}
```

---

### Update Execution Status

```http
POST /internal/update-status
```

**Headers:**

```http
X-N8N-Internal-Auth: your-internal-secret
```

**Request Body:**

```json
{
  "usage_log_id": "uuid",
  "status": "completed",
  "execution_time_ms": 1500,
  "error_message": null,
  "response_metadata": {}
}
```

**Status Values:**
- `pending`
- `running`
- `completed`
- `failed`
- `timeout`

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `bad_request` | 400 | Invalid request |
| `unauthorized` | 401 | Authentication failed |
| `forbidden` | 403 | Access denied |
| `not_found` | 404 | Resource not found |
| `conflict` | 409 | Resource already exists |
| `insufficient_credits` | 402 | Not enough credits |
| `rate_limit_exceeded` | 429 | Too many requests |
| `internal_error` | 500 | Server error |
| `n8n_error` | 502 | n8n error |
| `gateway_timeout` | 504 | Request timeout |

---

## SDKs

### Python

```python
import httpx
import hmac
import hashlib
import time
import json

class GatewayClient:
    def __init__(self, base_url: str, api_key: str, client_secret: str, tenant_id: str):
        self.base_url = base_url
        self.api_key = api_key
        self.client_secret = client_secret
        self.tenant_id = tenant_id
    
    def _sign_request(self, body: dict) -> tuple[str, str]:
        timestamp = str(int(time.time()))
        body_str = json.dumps(body)
        signature = hmac.new(
            self.client_secret.encode(),
            (timestamp + body_str).encode(),
            hashlib.sha256
        ).hexdigest()
        return timestamp, signature
    
    async def execute(self, workflow_id: str, data: dict) -> dict:
        body = {"workflow_id": workflow_id, "data": data}
        timestamp, signature = self._sign_request(body)
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/execute",
                json=body,
                headers={
                    "X-API-Key": self.api_key,
                    "X-Tenant-ID": self.tenant_id,
                    "X-Timestamp": timestamp,
                    "X-Signature": signature,
                }
            )
            return response.json()

# Usage
client = GatewayClient(
    base_url="https://api.example.com",
    api_key="gw_live_xxx",
    client_secret="secret",
    tenant_id="my-tenant"
)

result = await client.execute(
    workflow_id="uuid",
    data={"prompt": "Hello, world!"}
)
```

### JavaScript/TypeScript

```typescript
import crypto from 'crypto';

class GatewayClient {
  constructor(
    private baseUrl: string,
    private apiKey: string,
    private clientSecret: string,
    private tenantId: string
  ) {}

  private signRequest(body: object): { timestamp: string; signature: string } {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyStr = JSON.stringify(body);
    const signature = crypto
      .createHmac('sha256', this.clientSecret)
      .update(timestamp + bodyStr)
      .digest('hex');
    return { timestamp, signature };
  }

  async execute(workflowId: string, data: object): Promise<any> {
    const body = { workflow_id: workflowId, data };
    const { timestamp, signature } = this.signRequest(body);

    const response = await fetch(`${this.baseUrl}/api/v1/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
        'X-Tenant-ID': this.tenantId,
        'X-Timestamp': timestamp,
        'X-Signature': signature,
      },
      body: JSON.stringify(body),
    });

    return response.json();
  }
}

// Usage
const client = new GatewayClient(
  'https://api.example.com',
  'gw_live_xxx',
  'secret',
  'my-tenant'
);

const result = await client.execute('uuid', { prompt: 'Hello!' });
```
