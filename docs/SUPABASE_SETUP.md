# Supabase Setup Guide

This guide walks you through setting up Supabase for the N8N Orchestration Gateway.

## Prerequisites

- A Supabase account (https://supabase.com)
- A new or existing Supabase project

## Step 1: Create a New Project

1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Click "New Project"
3. Fill in:
   - **Name**: `n8n-gateway` (or your preferred name)
   - **Database Password**: Generate a strong password (save this!)
   - **Region**: Choose closest to your users
4. Click "Create new project"
5. Wait for project setup to complete (~2 minutes)

## Step 2: Get Your API Keys

1. In your project dashboard, go to **Settings** → **API**
2. Copy these values to your `.env` file:

```env
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

⚠️ **Security Warning**: 
- The `SUPABASE_SERVICE_ROLE_KEY` bypasses Row Level Security
- Never expose it to the client/browser
- Only use it in your backend application

## Step 3: Run the Migration

### Option A: Using Supabase SQL Editor

1. Go to **SQL Editor** in your Supabase dashboard
2. Click "New Query"
3. Copy the contents of `supabase/migrations/01_initial_schema.sql`
4. Click "Run" (or press Cmd/Ctrl + Enter)
5. Verify no errors in the output

### Option B: Using Supabase CLI

```bash
# Install Supabase CLI
npm install -g supabase

# Login to Supabase
supabase login

# Link your project
supabase link --project-ref your-project-ref

# Run migrations
supabase db push
```

## Step 4: Enable Required Extensions

The migration enables these extensions automatically, but verify they're active:

1. Go to **Database** → **Extensions**
2. Ensure these are enabled:
   - `uuid-ossp` - UUID generation
   - `pgcrypto` - Cryptographic functions
   - `vault` - Secret management (Supabase Vault)

If `vault` is not available (newer feature), you can use an alternative approach for credential storage (see below).

## Step 5: Verify Tables

Go to **Table Editor** and verify these tables exist:

- `profiles`
- `organizations`
- `organization_members`
- `workflows`
- `usage_logs`
- `invoices`
- `security_logs`
- `api_keys`

## Step 6: Verify RLS Policies

Go to **Authentication** → **Policies** and verify policies exist for each table.

## Step 7: Configure Clerk Integration (Third-Party Auth)

Supabase supports Clerk as a third-party auth provider:

### 7.1 Get Clerk JWKS URL

From your Clerk dashboard:
1. Go to **JWT Templates** → **Supabase**
2. Copy the JWKS URL (e.g., `https://your-instance.clerk.accounts.dev/.well-known/jwks.json`)

### 7.2 Configure Supabase

1. Go to **Authentication** → **Providers**
2. Enable "Third-party Auth"
3. Add your Clerk JWKS URL
4. Set the issuer to your Clerk instance URL

Alternatively, configure via SQL:

```sql
-- Enable third-party JWT validation
ALTER SYSTEM SET "supabase.auth.external_jwks_url" = 'https://your-instance.clerk.accounts.dev/.well-known/jwks.json';
```

## Step 8: Test the Setup

Run this query in SQL Editor to verify:

```sql
-- Test UUID generation
SELECT uuid_generate_v4();

-- Test profile creation
INSERT INTO profiles (id, email, name)
VALUES ('test_user_123', 'test@example.com', 'Test User')
RETURNING *;

-- Test organization creation
INSERT INTO organizations (name, owner_id, tenant_id, api_key_hash, api_key_prefix, credits)
VALUES ('Test Org', 'test_user_123', 'test-tenant', 'hash', 'gw_test_', 100)
RETURNING *;

-- Verify credit deduction function
SELECT * FROM fn_deduct_credits(
  (SELECT id FROM organizations WHERE tenant_id = 'test-tenant'),
  1,
  NULL,
  'test_user_123',
  '{"test": true}'::jsonb
);

-- Clean up test data
DELETE FROM organizations WHERE tenant_id = 'test-tenant';
DELETE FROM profiles WHERE id = 'test_user_123';
```

## Vault Setup (Credential Storage)

### If Vault Extension is Available

The migration automatically creates functions to store/retrieve tenant credentials:

```sql
-- Store credentials (encrypted at rest)
SELECT private.store_tenant_credentials(
  'org-uuid-here',
  '{"linkedin_api_key": "secret", "openai_key": "sk-xxx"}'::jsonb
);

-- Retrieve credentials (decrypted)
SELECT private.get_tenant_credentials('org-uuid-here');
```

### Alternative: Custom Encrypted Storage

If the Vault extension isn't available, use this alternative:

```sql
-- Create encrypted credentials table
CREATE TABLE tenant_credentials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  credentials_encrypted BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);

-- Enable RLS
ALTER TABLE tenant_credentials ENABLE ROW LEVEL SECURITY;

-- Only service role can access
CREATE POLICY "credentials_service_role" ON tenant_credentials
  FOR ALL
  USING (auth.role() = 'service_role');
```

Then handle encryption in your Python application using `cryptography` library.

## Production Configuration

### 1. Connection Pooling

For production, enable connection pooling:

1. Go to **Settings** → **Database**
2. Note the "Pooler" connection strings
3. Use the pooler URL in your application for better performance

### 2. Database Backups

Supabase handles automatic backups, but configure:

1. Go to **Database** → **Backups**
2. Verify daily backups are enabled
3. Consider enabling Point-in-Time Recovery (Pro plan)

### 3. Performance Monitoring

1. Enable **Database** → **Reports** for query insights
2. Monitor slow queries
3. Add indexes as needed based on usage patterns

### 4. Realtime (Optional)

If you need real-time updates:

1. Go to **Database** → **Publications**
2. Create a publication for tables you want to stream
3. Use Supabase client for realtime subscriptions

## Troubleshooting

### "Permission denied" Errors

- Verify RLS policies are correctly configured
- Check that you're using the service role key for admin operations
- Ensure the authenticated user has proper role in `organization_members`

### "Function not found" Errors

- Re-run the migration
- Check SQL syntax for your Supabase version
- Verify extensions are enabled

### Slow Queries

- Add indexes on frequently queried columns
- Use `EXPLAIN ANALYZE` to identify bottlenecks
- Consider partitioning `usage_logs` by date for large datasets

### Vault Not Available

- Use the alternative encrypted storage approach above
- Or use external secret management (AWS Secrets Manager, HashiCorp Vault)

## Database Schema Reference

### Tables

| Table | Purpose |
|-------|---------|
| `profiles` | User profiles (synced from Clerk) |
| `organizations` | Multi-tenant organizations |
| `organization_members` | User-organization membership |
| `workflows` | n8n workflow configurations |
| `usage_logs` | Execution logs for billing |
| `invoices` | Billing records |
| `security_logs` | Security event tracking |
| `api_keys` | Additional API keys |

### Key Functions

| Function | Purpose |
|----------|---------|
| `fn_deduct_credits` | Atomically deduct credits |
| `fn_add_credits` | Add credits after purchase |
| `fn_refund_credits` | Refund credits for failures |
| `fn_update_usage_status` | Update execution status |
| `private.store_tenant_credentials` | Store encrypted credentials |
| `private.get_tenant_credentials` | Retrieve decrypted credentials |

## Next Steps

After Supabase setup:

1. [Configure Clerk Authentication](CLERK_SETUP.md)
2. [Set up n8n Integration](N8N_SETUP.md)
3. [Deploy the Gateway](DEPLOYMENT.md)
