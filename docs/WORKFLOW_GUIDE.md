# Workflow Guide

Complete guide for creating, managing, and executing workflows through the N8N Orchestration Gateway.

## Overview

Workflows are the core abstraction of the gateway. Each workflow:
- Maps to an n8n webhook
- Belongs to an organization
- Has a credit cost per execution
- Can have custom timeout settings

## Creating Workflows

### 1. Create the n8n Workflow

First, create a webhook-triggered workflow in n8n:

```
Webhook Node → [Your Processing] → Response Node
```

**Webhook Configuration:**
- Path: `/webhook/my-workflow` (unique path)
- Method: POST
- Response Mode: "Last Node"

**Important Settings:**
- Authentication: None (gateway handles auth)
- Response Headers: Include execution info

### 2. Register in Gateway

Register the workflow via API:

```bash
curl -X POST http://localhost:8000/api/v1/workflows \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Workflow",
    "description": "Processes customer data",
    "n8n_workflow_id": "n8n-workflow-123",
    "n8n_webhook_path": "/webhook/my-workflow",
    "credits_per_execution": 1,
    "timeout_seconds": 300
  }'
```

Or via SQL:

```sql
INSERT INTO workflows (
    organization_id,
    name,
    description,
    n8n_workflow_id,
    n8n_webhook_path,
    credits_per_execution,
    timeout_seconds
) VALUES (
    'org-uuid',
    'My Workflow',
    'Processes customer data',
    'n8n-workflow-123',
    '/webhook/my-workflow',
    1,
    300
);
```

### 3. Workflow Schema

```typescript
interface Workflow {
  id: UUID;
  organization_id: UUID;
  name: string;
  description?: string;
  n8n_workflow_id: string;
  n8n_webhook_path: string;
  is_active: boolean;
  credits_per_execution: number;
  timeout_seconds: number;
  settings: {
    retry_on_failure?: boolean;
    max_retries?: number;
    input_schema?: JSONSchema;
    output_schema?: JSONSchema;
  };
  created_at: DateTime;
  updated_at: DateTime;
}
```

## Executing Workflows

### Basic Execution

```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "workflow-uuid-12345",
    "data": {
      "customer_id": "cust-123",
      "action": "process"
    }
  }'
```

### With Metadata

```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "workflow-uuid-12345",
    "data": {
      "customer_id": "cust-123"
    },
    "metadata": {
      "source": "mobile-app",
      "correlation_id": "req-abc-123",
      "user_agent": "MyApp/1.0"
    },
    "timeout_override": 120
  }'
```

### Streaming Execution

For long-running workflows:

```javascript
const response = await fetch(`${GATEWAY_URL}/api/v1/execute/stream`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    workflow_id: workflowId,
    data: inputData,
  }),
});

const reader = response.body.getReader();
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  console.log(new TextDecoder().decode(value));
}
```

## Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Gateway Execution Flow                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Authentication                                           │
│     └─► Validate JWT or API Key                             │
│                                                              │
│  2. Organization Verification                                │
│     └─► Check org is active                                 │
│                                                              │
│  3. Workflow Lookup                                          │
│     └─► Verify workflow exists and is active                │
│     └─► Check workflow belongs to org                       │
│                                                              │
│  4. Credit Deduction (Atomic)                               │
│     └─► Check sufficient credits                            │
│     └─► Deduct credits                                      │
│     └─► Create usage log entry                              │
│                                                              │
│  5. Credential Retrieval                                     │
│     └─► Fetch from Supabase Vault                           │
│     └─► (Optional) Acquire advisory lock                    │
│                                                              │
│  6. n8n Execution                                            │
│     └─► (Optional) Update n8n credentials via API           │
│     └─► POST to webhook with payload                        │
│     └─► Wait for response (with timeout)                    │
│                                                              │
│  7. Result Processing                                        │
│     └─► Update usage log with result                        │
│     └─► (On failure) Refund credits                         │
│     └─► Return response to client                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Execution States

| Status | Description | Credits |
|--------|-------------|---------|
| `pending` | Execution created, waiting to run | Reserved |
| `running` | Currently executing in n8n | Reserved |
| `completed` | Successfully finished | Consumed |
| `failed` | Error during execution | Refunded |
| `timeout` | Exceeded timeout limit | Not refunded* |

*Timeouts don't refund because the workflow may still complete in n8n.

## Error Handling

### Client-Side Errors (4xx)

```json
{
  "error": "validation_error",
  "message": "workflow_id is required",
  "request_id": "req-123"
}
```

### Credit Errors (402)

```json
{
  "error": "insufficient_credits",
  "message": "Insufficient credits. Required: 1, Available: 0",
  "credits_required": 1,
  "credits_available": 0
}
```

### n8n Errors (5xx)

```json
{
  "error": "n8n_error",
  "message": "n8n server error (500): Internal error",
  "execution_id": "exec-123"
}
```

### Timeout Errors (504)

```json
{
  "error": "gateway_timeout",
  "message": "Request to n8n timed out after 300s",
  "execution_id": "exec-123"
}
```

## Workflow Patterns

### Pattern 1: Simple Data Processing

```
┌─────────┐    ┌───────────┐    ┌──────────┐
│ Webhook │───►│ Transform │───►│ Respond  │
└─────────┘    └───────────┘    └──────────┘
```

n8n workflow:
```json
{
  "nodes": [
    {
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "parameters": {"path": "transform"}
    },
    {
      "name": "Transform",
      "type": "n8n-nodes-base.code",
      "parameters": {
        "jsCode": "return [{json: {result: $input.first().json.data}}]"
      }
    },
    {
      "name": "Respond",
      "type": "n8n-nodes-base.respondToWebhook"
    }
  ]
}
```

### Pattern 2: External API Integration

```
┌─────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────┐
│ Webhook │───►│ Get Secrets │───►│ Call API  │───►│ Respond  │
└─────────┘    └─────────────┘    └───────────┘    └──────────┘
```

Accessing secrets in n8n:
```javascript
// Using payload injection
const apiKey = $input.first().json.secrets?.openai?.api_key;

// Using n8n credentials (with dynamic injection)
// Credential is pre-configured by gateway before execution
```

### Pattern 3: Multi-Step Processing

```
┌─────────┐    ┌─────────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐
│ Webhook │───►│ Validate│───►│ Process  │───►│ Notify  │───►│ Respond  │
└─────────┘    └─────────┘    └──────────┘    └─────────┘    └──────────┘
```

### Pattern 4: Async with Callback

```
┌─────────┐    ┌──────────────┐    ┌─────────────────┐
│ Webhook │───►│ Start Async  │───►│ Return exec_id  │
└─────────┘    │ Processing   │    └─────────────────┘
               └──────┬───────┘
                      │
                      ▼
               ┌──────────────┐    ┌───────────────────┐
               │ Long Process │───►│ Callback to       │
               └──────────────┘    │ Gateway (status)  │
                                   └───────────────────┘
```

## Best Practices

### 1. Input Validation

Add input schema to workflow settings:

```json
{
  "settings": {
    "input_schema": {
      "type": "object",
      "required": ["customer_id"],
      "properties": {
        "customer_id": {"type": "string"},
        "action": {"enum": ["create", "update", "delete"]}
      }
    }
  }
}
```

### 2. Idempotency

Use `execution_id` to prevent duplicate processing:

```javascript
// In n8n Code node
const executionId = $input.first().json.execution_id;

// Check if already processed
const existing = await checkProcessed(executionId);
if (existing) {
  return existing.result;
}
```

### 3. Error Handling

Always return structured errors:

```javascript
try {
  // Processing
  return [{json: {success: true, data: result}}];
} catch (error) {
  return [{json: {
    success: false,
    error: {
      type: error.name,
      message: error.message
    }
  }}];
}
```

### 4. Timeouts

Set appropriate timeouts:

```javascript
// Quick operations: 30-60 seconds
// API integrations: 60-120 seconds
// Complex processing: 120-300 seconds
// Long-running: Use streaming endpoint
```

### 5. Credit Costing

Consider workflow complexity:

| Workflow Type | Suggested Credits |
|---------------|------------------|
| Simple transform | 1 |
| Single API call | 1-2 |
| Multiple API calls | 2-5 |
| AI/ML processing | 5-10 |
| Complex pipeline | 10+ |

## Monitoring

### Usage Logs

Query execution history:

```sql
SELECT 
    ul.id,
    w.name as workflow_name,
    ul.credits_used,
    ul.status,
    ul.execution_time_ms,
    ul.created_at
FROM usage_logs ul
JOIN workflows w ON w.id = ul.workflow_id
WHERE ul.organization_id = 'org-uuid'
ORDER BY ul.created_at DESC
LIMIT 100;
```

### Execution Metrics

```sql
-- Average execution time by workflow
SELECT 
    w.name,
    AVG(ul.execution_time_ms) as avg_time_ms,
    COUNT(*) as total_executions,
    COUNT(*) FILTER (WHERE ul.status = 'completed') as successful
FROM usage_logs ul
JOIN workflows w ON w.id = ul.workflow_id
WHERE ul.created_at > NOW() - INTERVAL '7 days'
GROUP BY w.id, w.name;
```

### Error Analysis

```sql
-- Recent errors
SELECT 
    w.name,
    ul.error_message,
    ul.created_at
FROM usage_logs ul
JOIN workflows w ON w.id = ul.workflow_id
WHERE ul.status = 'failed'
AND ul.created_at > NOW() - INTERVAL '24 hours'
ORDER BY ul.created_at DESC;
```
