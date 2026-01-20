# n8n Setup Guide

This guide covers how to configure your n8n instance to work with the N8N Orchestration Gateway.

## Prerequisites

- A running n8n instance (self-hosted or n8n.cloud)
- Admin access to create and configure workflows
- Gateway already deployed and running

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Client App     │────▶│  Gateway API    │────▶│  n8n Instance   │
│                 │     │                 │     │                 │
│ - JWT/API Key   │     │ - Auth          │     │ - Webhooks      │
│ - Workflow ID   │     │ - Credits       │     │ - Workflows     │
│ - Input Data    │     │ - Credentials   │     │ - Executions    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │
                                │ X-N8N-Internal-Auth
                                │ + Injected Secrets
                                ▼
                        ┌─────────────────┐
                        │ n8n Workflow    │
                        │                 │
                        │ 1. Webhook Node │
                        │ 2. Your Logic   │
                        │ 3. Response     │
                        └─────────────────┘
```

## Step 1: Configure Internal Authentication

### 1.1 Set Gateway Secret in n8n

Add an environment variable to your n8n instance:

```bash
# Docker
docker run -d \
  -e N8N_CUSTOM_HEADER_AUTH_KEY="X-N8N-Internal-Auth" \
  -e N8N_CUSTOM_HEADER_AUTH_VALUE="your-gateway-internal-secret" \
  n8nio/n8n

# Docker Compose
environment:
  - N8N_CUSTOM_HEADER_AUTH_KEY=X-N8N-Internal-Auth
  - N8N_CUSTOM_HEADER_AUTH_VALUE=your-gateway-internal-secret

# Kubernetes ConfigMap
data:
  N8N_CUSTOM_HEADER_AUTH_KEY: X-N8N-Internal-Auth
  N8N_CUSTOM_HEADER_AUTH_VALUE: your-gateway-internal-secret
```

### 1.2 Use the Same Secret in Gateway

Ensure your gateway `.env` has the matching secret:

```env
N8N_INTERNAL_AUTH_SECRET=your-gateway-internal-secret
```

⚠️ **Important**: This secret should be:
- At least 64 characters long in production
- Generated with `openssl rand -hex 32`
- Stored securely (not in version control)

## Step 2: Create Webhook-Enabled Workflow

### 2.1 Basic Workflow Structure

Create a new workflow in n8n with this structure:

```
[Webhook Trigger] → [Your Processing Logic] → [Respond to Webhook]
```

### 2.2 Configure Webhook Node

1. Add a **Webhook** node as the trigger
2. Configure:
   - **HTTP Method**: POST
   - **Path**: `/your-workflow-path` (e.g., `/linkedin-summarizer`)
   - **Response Mode**: **"Last Node"** or **"When Last Node Finishes"**
   
   ⚠️ **Critical**: The Response Mode setting prevents the gateway from timing out while waiting for async operations.

3. Copy the **Production URL** - you'll need this for workflow registration

### 2.3 Access Injected Data

The gateway sends data in this format:

```json
{
  "data": {
    // Original client input
  },
  "secrets": {
    // Decrypted tenant credentials from Vault
    "linkedin_api_key": "xxx",
    "openai_key": "sk-xxx"
  },
  "execution_id": "uuid-for-tracking",
  "timestamp": 1700000000
}
```

In your workflow, access these using expressions:

```javascript
// Access input data
{{ $json.data.your_field }}

// Access injected secrets
{{ $json.secrets.linkedin_api_key }}
{{ $json.secrets.openai_key }}

// Access execution ID (for callbacks)
{{ $json.execution_id }}
```

### 2.4 Verify Internal Auth (Optional but Recommended)

Add an **IF** node after the Webhook to verify the request came from the gateway:

```javascript
// IF node condition
{{ $request.headers['x-n8n-internal-auth'] === 'your-gateway-internal-secret' }}
```

This adds defense-in-depth even if your n8n instance is on a private network.

## Step 3: Create Error Workflow

### 3.1 Global Error Workflow

Create a workflow that catches errors from all other workflows:

```
[Error Trigger] → [HTTP Request to Gateway] → [Logging/Alerting]
```

### 3.2 Configure Error Trigger

1. Add an **Error Trigger** node
2. Set it to trigger on all workflow errors (or specific workflows)

### 3.3 Send Error to Gateway

Add an **HTTP Request** node:

```
Method: POST
URL: https://your-gateway.com/api/v1/internal/log-error
Headers:
  - X-N8N-Internal-Auth: {{ $env.N8N_INTERNAL_AUTH_SECRET }}
  - Content-Type: application/json
Body (JSON):
{
  "workflow_id": "{{ $json.workflow.id }}",
  "execution_id": "{{ $json.execution.id }}",
  "error_message": "{{ $json.execution.error.message }}",
  "error_stack": "{{ $json.execution.error.stack }}",
  "timestamp": "{{ $now.toISO() }}",
  "metadata": {
    "workflow_name": "{{ $json.workflow.name }}",
    "node_name": "{{ $json.execution.lastNodeExecuted }}"
  }
}
```

### 3.4 Set as Global Error Workflow

1. Go to n8n **Settings** → **Workflow Settings**
2. Set your error workflow as the global error handler
3. Or set it per-workflow in workflow settings

## Step 4: Register Workflow in Gateway

### 4.1 Via API

```bash
curl -X POST https://your-gateway.com/api/v1/workflows \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "LinkedIn Summarizer",
    "description": "Summarizes LinkedIn profiles using AI",
    "n8n_workflow_id": "wf_abc123",
    "n8n_webhook_path": "/webhook/linkedin-summarizer",
    "credits_per_execution": 2,
    "timeout_seconds": 300,
    "settings": {
      "retry_on_failure": true,
      "max_retries": 3
    }
  }' \
  -G -d "org_id=your-org-uuid"
```

### 4.2 Store Tenant Credentials

Store the credentials that will be injected into workflows:

```bash
curl -X POST https://your-gateway.com/api/v1/organizations/{org_id}/credentials \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "linkedin_api_key": "your-linkedin-key",
    "openai_key": "sk-your-openai-key",
    "custom_service_token": "abc123"
  }'
```

## Step 5: Test the Integration

### 5.1 Test Webhook Directly

First, test the n8n webhook directly:

```bash
curl -X POST https://your-n8n.com/webhook/linkedin-summarizer \
  -H "X-N8N-Internal-Auth: your-gateway-internal-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {"linkedin_url": "https://linkedin.com/in/example"},
    "secrets": {"openai_key": "test"},
    "execution_id": "test-123",
    "timestamp": 1700000000
  }'
```

### 5.2 Test Through Gateway

Then test through the gateway:

```bash
curl -X POST https://your-gateway.com/api/v1/execute \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "workflow-uuid-from-step-4",
    "data": {
      "linkedin_url": "https://linkedin.com/in/example"
    }
  }'
```

## Workflow Examples

### Example 1: AI Content Generator

```
[Webhook] → [OpenAI Chat] → [Format Response] → [Respond to Webhook]
```

OpenAI node configuration:
```javascript
// Model
gpt-4

// Messages
System: You are a helpful assistant.
User: {{ $json.data.prompt }}

// API Key (from injected secrets)
{{ $json.secrets.openai_key }}
```

### Example 2: LinkedIn Profile Summarizer

```
[Webhook] → [HTTP Request (LinkedIn)] → [OpenAI Summary] → [Respond]
```

### Example 3: Multi-Step Data Pipeline

```
[Webhook] → [Fetch Data] → [Transform] → [Store in DB] → [Respond]
                                              ↓
                                    [Async Notification]
```

## Best Practices

### 1. Always Set Response Mode

Set Webhook **Response Mode** to "Last Node" to prevent gateway timeouts.

### 2. Handle Errors Gracefully

```javascript
// In a Code node
try {
  // Your logic
  return { success: true, data: result };
} catch (error) {
  return { success: false, error: error.message };
}
```

### 3. Use Execution ID for Tracking

Pass the `execution_id` through your workflow for debugging:

```javascript
// Include in all HTTP requests for tracing
{{ $json.execution_id }}
```

### 4. Validate Input Data

Add validation before processing:

```javascript
// IF node to check required fields
{{ $json.data.required_field !== undefined }}
```

### 5. Keep Secrets Secure

- Never log secrets
- Use secrets only in secure nodes (HTTP Request with HTTPS)
- Don't expose secrets in responses

### 6. Set Appropriate Timeouts

Configure workflow timeouts to be less than gateway timeout:

- Gateway default: 300 seconds
- Workflow should complete in < 290 seconds

### 7. Implement Idempotency

Use `execution_id` to prevent duplicate processing:

```javascript
// Check if already processed
const processed = await checkDatabase(executionId);
if (processed) return existingResult;
```

## Troubleshooting

### Webhook Not Responding

1. Check n8n is running and accessible
2. Verify webhook URL is correct
3. Check Response Mode is set correctly
4. Review n8n execution logs

### Authentication Failing

1. Verify `X-N8N-Internal-Auth` header matches
2. Check for typos in secret
3. Ensure header name is exact (case-sensitive)

### Timeouts

1. Reduce workflow complexity
2. Add caching for expensive operations
3. Increase timeout in workflow registration
4. Use async callbacks for long operations

### Secrets Not Available

1. Verify credentials are stored in gateway
2. Check organization ID matches
3. Ensure Vault is properly configured

### Error Workflow Not Triggering

1. Verify error workflow is set as global handler
2. Check error workflow itself doesn't have errors
3. Test error workflow independently

## Security Recommendations

1. **Network Isolation**: Keep n8n on a private network, accessible only from gateway
2. **HTTPS Only**: Use HTTPS for all webhook URLs
3. **Secret Rotation**: Rotate `N8N_INTERNAL_AUTH_SECRET` periodically
4. **Audit Logging**: Enable n8n execution logging
5. **Access Control**: Limit who can create/edit workflows
6. **Input Validation**: Always validate input in workflows

## Next Steps

1. [Deploy to Production](DEPLOYMENT.md)
2. [Set up Monitoring](MONITORING.md)
3. [Configure Billing Integration](BILLING.md)
