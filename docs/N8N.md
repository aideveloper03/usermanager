# n8n Connection Guide

This gateway proxies requests to a private n8n webhook and streams the response
back to the client. Follow the steps below to configure your n8n instance.

## 1) Webhook Node Response Mode

In the Webhook node:

- Set **Response Mode** to **Last Node** or **When Last Node Finishes**.
- This prevents the gateway from timing out while downstream AI processing runs.

## 2) Internal Auth Header

The gateway adds `X-N8N-Internal-Auth` to every outbound request. Use an
expression to validate it instead of hardcoding.

Example (Webhook Node → Authentication → Header):

```
Name: X-N8N-Internal-Auth
Value: {{$env.N8N_INTERNAL_SECRET}}
```

Match `N8N_INTERNAL_SECRET` with the gateway environment variable.

## 3) Error Workflow Callback

Create a global **Error Workflow** that calls back into the gateway:

**HTTP Request Node**

- Method: `POST`
- URL: `https://<gateway-host>/api/v1/internal/log-error`
- Headers:
  - `X-N8N-Internal-Auth: {{$env.N8N_INTERNAL_SECRET}}`
- Body:
  ```json
  {
    "org_id": "{{$json.org_id}}",
    "workflow_id": "{{$json.workflow.id}}",
    "error_message": "{{$json.error.message}}",
    "metadata": {
      "execution_id": "{{$json.execution.id}}"
    }
  }
  ```

This records failures in `usage_logs` for your SaaS dashboard.

## 4) Test the Connection

Send a test request through the gateway `/api/v1/execute` endpoint and confirm:

- n8n receives the payload in `data`.
- Secrets are injected into `secrets`.
- The response is streamed back to the gateway client.
