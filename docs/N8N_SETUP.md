# n8n Setup Guide

Complete guide for integrating n8n with the Orchestration Gateway.

## Prerequisites

- n8n instance (self-hosted or n8n Cloud)
- Admin access to n8n
- Understanding of n8n webhooks

## 1. n8n Deployment Options

### Option A: Docker (Recommended for Development)

```yaml
# docker-compose.yml (included in project)
n8n:
  image: n8nio/n8n:latest
  ports:
    - "5678:5678"
  environment:
    - N8N_BASIC_AUTH_ACTIVE=false
    - N8N_HOST=n8n
    - N8N_PORT=5678
    - WEBHOOK_URL=http://n8n:5678/
  volumes:
    - n8n-data:/home/node/.n8n
```

### Option B: Self-Hosted Production

See [n8n Self-Hosting Guide](https://docs.n8n.io/hosting/)

### Option C: n8n Cloud

Use n8n Cloud at [app.n8n.io](https://app.n8n.io)

## 2. Configure Internal Authentication

The gateway uses a shared secret to authenticate with n8n:

### In n8n:

1. Create a Header Auth credential:
   - Name: "Gateway Internal Auth"
   - Header Name: `X-N8N-Internal-Auth`
   - Header Value: `your-64-character-secret`

2. Or use environment variable:
   ```bash
   N8N_CUSTOM_HEADER_AUTH=true
   N8N_CUSTOM_HEADER_NAME=X-N8N-Internal-Auth
   N8N_CUSTOM_HEADER_VALUE=your-64-character-secret
   ```

### In Gateway:

```bash
# .env
N8N_BASE_URL=http://your-n8n-instance:5678
N8N_INTERNAL_AUTH_SECRET=your-64-character-secret
```

## 3. Create Workflow Templates

### Basic Webhook Workflow

```json
{
  "name": "Gateway Example Workflow",
  "nodes": [
    {
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "parameters": {
        "path": "gateway-example",
        "httpMethod": "POST",
        "responseMode": "lastNode"
      }
    },
    {
      "name": "Process Data",
      "type": "n8n-nodes-base.code",
      "parameters": {
        "jsCode": "// Access input data\nconst inputData = $input.first().json.data;\n\n// Access injected secrets (if using payload injection)\nconst secrets = $input.first().json.secrets || {};\n\n// Process and return\nreturn [{\n  json: {\n    processed: true,\n    input: inputData,\n    timestamp: new Date().toISOString()\n  }\n}];"
      }
    }
  ]
}
```

### Workflow with Credential Access

```json
{
  "name": "OpenAI Workflow",
  "nodes": [
    {
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "parameters": {
        "path": "openai-process",
        "httpMethod": "POST"
      }
    },
    {
      "name": "OpenAI",
      "type": "n8n-nodes-base.openAi",
      "parameters": {
        "operation": "text",
        "model": "gpt-4",
        "prompt": "={{$json.data.prompt}}"
      },
      "credentials": {
        "openAiApi": {
          "id": "cred_openai_base",
          "name": "OpenAI Base Credential"
        }
      }
    }
  ]
}
```

## 4. Dynamic Credential Injection

The gateway supports two methods for credential injection:

### Method 1: Payload Injection (Simple)

Credentials are passed in the webhook payload:

```javascript
// In n8n Code node
const secrets = $input.first().json.secrets;
const apiKey = secrets?.openai?.api_key;

// Use the API key directly
const response = await fetch('https://api.openai.com/v1/chat/completions', {
  headers: {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({...})
});
```

### Method 2: Dynamic Credential Update (Secure)

The gateway updates n8n credentials via REST API before execution:

1. **Enable n8n REST API:**
   ```bash
   N8N_PUBLIC_API_DISABLED=false
   ```

2. **Create API Key in n8n:**
   - Settings → API → Create API Key

3. **Configure Gateway:**
   ```bash
   N8N_API_KEY=your-n8n-api-key
   N8N_USE_DYNAMIC_CREDENTIALS=true
   ```

4. **Register Base Credentials:**
   ```sql
   -- In Supabase
   INSERT INTO n8n_base_credentials (service_type, n8n_credential_id, description)
   VALUES 
     ('openai', 'cred_openai_123', 'Base OpenAI credential'),
     ('slack', 'cred_slack_456', 'Base Slack credential');
   ```

5. **How it works:**
   - Gateway acquires advisory lock for the tenant
   - Fetches tenant-specific credentials from Vault
   - PATCHes the base credential in n8n with tenant data
   - Executes the webhook
   - Lock is released when transaction completes

## 5. Error Handling

### Callback Workflow

Create a workflow to handle execution status updates:

```json
{
  "name": "Gateway Status Callback",
  "nodes": [
    {
      "name": "Status Webhook",
      "type": "n8n-nodes-base.webhook",
      "parameters": {
        "path": "gateway-status",
        "httpMethod": "POST"
      }
    },
    {
      "name": "Update Gateway",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "method": "POST",
        "url": "={{$env.GATEWAY_URL}}/api/v1/internal/update-status",
        "headers": {
          "X-N8N-Internal-Auth": "={{$env.GATEWAY_SECRET}}"
        },
        "body": {
          "execution_id": "={{$json.execution_id}}",
          "status": "={{$json.status}}",
          "data": "={{$json.result}}"
        }
      }
    }
  ]
}
```

### Error Logging

```json
{
  "name": "Error Handler",
  "type": "n8n-nodes-base.errorTrigger",
  "parameters": {}
},
{
  "name": "Log to Gateway",
  "type": "n8n-nodes-base.httpRequest",
  "parameters": {
    "method": "POST",
    "url": "={{$env.GATEWAY_URL}}/api/v1/internal/log-error",
    "body": {
      "execution_id": "={{$execution.id}}",
      "error_type": "={{$json.error.name}}",
      "error_message": "={{$json.error.message}}"
    }
  }
}
```

## 6. Webhook Security

### Validate Internal Auth Header

In your webhook workflows, add validation:

```javascript
// Code node at start of workflow
const internalSecret = $env.GATEWAY_SECRET;
const providedSecret = $input.first().headers['x-n8n-internal-auth'];

if (providedSecret !== internalSecret) {
  throw new Error('Unauthorized: Invalid internal auth header');
}

// Continue processing
return $input.all();
```

### IP Allowlisting

Configure n8n to only accept connections from the gateway:

```bash
# n8n environment
N8N_ALLOWED_IPS=10.0.0.0/8,172.16.0.0/12
```

## 7. Testing Workflows

### Manual Test

```bash
curl -X POST http://localhost:5678/webhook/gateway-example \
  -H "Content-Type: application/json" \
  -H "X-N8N-Internal-Auth: your-secret" \
  -d '{
    "data": {"message": "Hello"},
    "execution_id": "test-123",
    "timestamp": 1700000000
  }'
```

### Integration Test

```python
# tests/test_n8n_integration.py
import pytest
from app.services.n8n_client import N8NClient

@pytest.mark.integration
async def test_webhook_execution():
    client = N8NClient(
        base_url="http://localhost:5678",
        internal_auth_secret="your-secret"
    )
    
    result = await client.execute_webhook(
        webhook_path="/webhook/gateway-example",
        data={"message": "test"},
        timeout=30
    )
    
    assert result["success"] is True
```

## 8. Performance Tuning

### Connection Pooling

```bash
# n8n environment
N8N_CONCURRENCY_PRODUCTION_LIMIT=100
```

### Webhook Timeout

```bash
# Gateway environment
N8N_REQUEST_TIMEOUT=300  # 5 minutes max
```

### Queue Configuration

For high-volume workflows, enable Redis queue:

```bash
# n8n environment
EXECUTIONS_MODE=queue
QUEUE_BULL_REDIS_HOST=redis
```

## 9. Monitoring

### Health Check

```bash
curl http://localhost:5678/healthz
```

### Execution Metrics

Enable metrics endpoint:

```bash
N8N_METRICS=true
N8N_METRICS_PREFIX=n8n_
```

Access at: `http://localhost:5678/metrics`

## 10. Production Checklist

- [ ] Internal auth secret is 64+ characters
- [ ] n8n is not publicly accessible (behind firewall/VPN)
- [ ] SSL/TLS enabled for all connections
- [ ] Database backups configured
- [ ] Error webhook set up for monitoring
- [ ] Rate limiting configured
- [ ] Execution timeout set appropriately
- [ ] Logs are being collected
