# API Reference

Complete API documentation for the N8N Orchestration Gateway.

## Base URL

```
Production: https://your-gateway.example.com
Development: http://localhost:8000
```

## Authentication

### Clerk JWT Authentication

Include the JWT token in the Authorization header:

```http
Authorization: Bearer <clerk-jwt-token>
```

The JWT must include:
- `sub`: Clerk user ID
- `org_id`: Organization ID (optional, can use X-Tenant-ID header instead)
- `exp`: Expiration timestamp

### API Key Authentication

For server-to-server communication:

```http
X-API-Key: gw_live_xxxxxxxxxxxx
X-Tenant-ID: your-tenant-id
X-Timestamp: 1700000000
X-Signature: <hmac-sha256-signature>
```

**Computing the HMAC Signature:**

```python
import hmac
import hashlib
import time
import json

def compute_signature(client_secret: str, timestamp: str, body: bytes) -> str:
    message = timestamp.encode() + body
    return hmac.new(
        client_secret.encode(),
        message,
        hashlib.sha256
    ).hexdigest()

# Example usage
timestamp = str(int(time.time()))
body = json.dumps({"workflow_id": "xxx", "data": {}}).encode()
signature = compute_signature("your-client-secret", timestamp, body)
```

### Developer Bypass (Development Only)

When `DEV_SKIP_AUTH=true`:

```http
X-Dev-User-ID: test_user_123
X-Dev-Org-ID: test_org_123
X-Dev-Role: admin
```

---

## Endpoints

### Health Check

#### GET /api/v1/health

Check gateway health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "ok",
    "n8n": "ok",
    "redis": "ok"
  }
}
```

---

### Workflow Execution

#### POST /api/v1/execute

Execute an n8n workflow.

**Request Headers:**
```http
Authorization: Bearer <token>
Content-Type: application/json
X-Tenant-ID: your-tenant-id (optional with JWT)
```

**Request Body:**
```json
{
  "workflow_id": "550e8400-e29b-41d4-a716-446655440000",
  "data": {
    "input": "your input data",
    "parameters": {
      "key": "value"
    }
  },
  "metadata": {
    "source": "api",
    "correlation_id": "abc-123"
  },
  "timeout_override": 120
}
```

**Parameters:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `workflow_id` | UUID | Yes | ID of the workflow to execute |
| `data` | object | Yes | Input data for the workflow |
| `metadata` | object | No | Additional metadata for logging |
| `timeout_override` | integer | No | Custom timeout in seconds (max: 600) |

**Success Response (200):**
```json
{
  "success": true,
  "execution_id": "exec-uuid-12345",
  "status": "completed",
  "data": {
    "result": "workflow output"
  },
  "credits_used": 1,
  "credits_remaining": 999,
  "execution_time_ms": 150
}
```

**Error Responses:**

*402 Insufficient Credits:*
```json
{
  "error": "insufficient_credits",
  "message": "Insufficient credits. Required: 1, Available: 0",
  "credits_required": 1,
  "credits_available": 0
}
```

*404 Workflow Not Found:*
```json
{
  "error": "not_found",
  "message": "Workflow 550e8400-e29b-41d4-a716-446655440000 not found or inactive"
}
```

*504 Gateway Timeout:*
```json
{
  "error": "gateway_timeout",
  "message": "Request to n8n timed out after 300s",
  "execution_id": "exec-uuid-12345"
}
```

---

#### POST /api/v1/execute/stream

Execute a workflow with streaming response.

Same request format as `/api/v1/execute`, but returns a streaming response with chunks as they become available.

**Response Headers:**
```http
Content-Type: application/json
X-Execution-ID: exec-uuid-12345
X-Request-ID: req-uuid-67890
Transfer-Encoding: chunked
```

---

### Workflows

#### GET /api/v1/workflows

List all workflows for the authenticated organization.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `active_only` | boolean | true | Only return active workflows |
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response:**
```json
[
  {
    "id": "workflow-uuid-12345",
    "name": "Process Customer Data",
    "description": "Processes and validates customer data",
    "n8n_workflow_id": "n8n-123",
    "is_active": true,
    "credits_per_execution": 1,
    "timeout_seconds": 300,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

---

#### GET /api/v1/workflows/{workflow_id}

Get a specific workflow.

**Response:**
```json
{
  "id": "workflow-uuid-12345",
  "name": "Process Customer Data",
  "description": "Processes and validates customer data",
  "n8n_workflow_id": "n8n-123",
  "n8n_webhook_path": "/webhook/process-customer",
  "is_active": true,
  "credits_per_execution": 1,
  "timeout_seconds": 300,
  "settings": {
    "retry_on_failure": false,
    "max_retries": 3,
    "input_schema": null,
    "output_schema": null
  },
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

---

#### POST /api/v1/workflows

Create a new workflow (Admin only).

**Request Body:**
```json
{
  "name": "New Workflow",
  "description": "Description of the workflow",
  "n8n_workflow_id": "n8n-new-123",
  "n8n_webhook_path": "/webhook/new-workflow",
  "credits_per_execution": 2,
  "timeout_seconds": 120
}
```

**Response (201):**
```json
{
  "id": "workflow-uuid-new",
  "name": "New Workflow",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### Organizations

#### GET /api/v1/organizations

List organizations the user belongs to.

**Response:**
```json
[
  {
    "id": "org-uuid-12345",
    "name": "My Company",
    "tenant_id": "my-company",
    "credits": 1000,
    "plan_type": "professional",
    "role": "owner",
    "is_active": true
  }
]
```

---

#### GET /api/v1/organizations/{org_id}

Get organization details.

**Response:**
```json
{
  "id": "org-uuid-12345",
  "name": "My Company",
  "tenant_id": "my-company",
  "credits": 1000,
  "plan_type": "professional",
  "is_active": true,
  "settings": {
    "webhook_url": null,
    "allowed_ips": [],
    "rate_limit_override": null
  },
  "created_at": "2024-01-01T00:00:00Z"
}
```

---

#### POST /api/v1/organizations

Create a new organization.

**Request Body:**
```json
{
  "name": "New Company",
  "tenant_id": "new-company",
  "plan_type": "starter"
}
```

**Response (201):**
```json
{
  "id": "org-uuid-new",
  "name": "New Company",
  "tenant_id": "new-company",
  "api_key": "gw_live_xxxxxxxxxxxxx",
  "client_secret": "secret_xxxxxxxxxxxxx",
  "credits": 100,
  "message": "Save these credentials securely - they won't be shown again!"
}
```

---

### Credits & Usage

#### GET /api/v1/organizations/{org_id}/usage

Get usage logs for an organization.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |
| `status` | string | null | Filter by status |

**Response:**
```json
{
  "usage_logs": [
    {
      "id": "usage-uuid-12345",
      "workflow_id": "workflow-uuid-12345",
      "workflow_name": "Process Customer Data",
      "credits_used": 1,
      "status": "completed",
      "execution_time_ms": 150,
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:30:01Z"
    }
  ],
  "total": 100,
  "credits_remaining": 900
}
```

---

#### POST /api/v1/organizations/{org_id}/credits

Add credits to an organization (Admin only).

**Request Body:**
```json
{
  "amount": 1000,
  "invoice_id": "inv-uuid-12345"
}
```

**Response:**
```json
{
  "success": true,
  "new_balance": 2000,
  "amount_added": 1000
}
```

---

### Internal Callbacks

These endpoints are called by n8n workflows and use internal authentication.

#### POST /api/v1/internal/update-status

Update execution status from n8n.

**Headers:**
```http
X-N8N-Internal-Auth: <internal-secret>
```

**Request Body:**
```json
{
  "execution_id": "exec-uuid-12345",
  "status": "completed",
  "data": {"result": "success"},
  "execution_time_ms": 150
}
```

---

#### POST /api/v1/internal/log-error

Log an error from n8n workflow.

**Request Body:**
```json
{
  "execution_id": "exec-uuid-12345",
  "error_type": "validation_error",
  "error_message": "Invalid input format",
  "stack_trace": "..."
}
```

---

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `bad_request` | Invalid request format or parameters |
| 401 | `unauthorized` | Missing or invalid authentication |
| 402 | `insufficient_credits` | Not enough credits for execution |
| 403 | `forbidden` | Access denied / Invalid HMAC |
| 404 | `not_found` | Resource not found |
| 422 | `validation_error` | Request validation failed |
| 429 | `rate_limited` | Too many requests |
| 500 | `internal_error` | Server error |
| 502 | `n8n_error` | n8n webhook error |
| 504 | `gateway_timeout` | n8n request timeout |

## Rate Limiting

Default limits:
- 100 requests per 60 seconds per tenant
- 10 requests per second burst

Rate limit headers:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1700000060
```

## Webhooks

### Clerk User Sync

Endpoint: `POST /api/v1/webhooks/clerk`

Handles Clerk webhook events for user synchronization:
- `user.created`: Creates profile in database
- `user.updated`: Updates profile
- `user.deleted`: Deactivates profile

### Stripe Billing (Optional)

Endpoint: `POST /api/v1/webhooks/stripe`

Handles Stripe webhook events:
- `invoice.paid`: Adds credits to organization
- `invoice.payment_failed`: Logs failed payment
