# Supabase Setup Guide

Complete guide for setting up Supabase with Clerk Native Integration for the N8N Orchestration Gateway.

## Prerequisites

- Supabase account and project
- Clerk account with application
- Basic understanding of PostgreSQL and RLS

## 1. Create Supabase Project

1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Click "New Project"
3. Enter project details:
   - Name: `n8n-gateway`
   - Database Password: (save this securely)
   - Region: Choose closest to your users
4. Wait for project to be provisioned

## 2. Configure Clerk Native Integration

### In Clerk Dashboard:

1. Go to your Clerk application
2. Navigate to **Integrations** → **Supabase**
3. Click "Enable Supabase Integration"
4. Copy the **JWT Template** (this is auto-generated)

### In Supabase Dashboard:

1. Go to **Settings** → **API**
2. Under **JWT Settings**, add Clerk as a JWT issuer:
   - Issuer URL: `https://your-instance.clerk.accounts.dev`
   - JWKS URL: `https://your-instance.clerk.accounts.dev/.well-known/jwks.json`

3. Or, go to **Authentication** → **Providers** and enable Clerk:
   ```sql
   -- Alternative: Configure via SQL
   ALTER SYSTEM SET "pgrst.jwt_secret" TO 'your-jwt-secret';
   ```

## 3. Apply Database Migrations

### Migration 1: Initial Schema

Run `supabase/migrations/01_initial_schema.sql` in the SQL Editor:

This creates:
- `profiles` table (TEXT id for Clerk user IDs)
- `organizations` table with API key management
- `organization_members` junction table
- `workflows` table
- `usage_logs` for billing
- `invoices` for payments
- `security_logs` for audit trail
- `api_keys` for additional keys
- Base RLS policies
- Credit management RPCs

### Migration 2: Clerk Native Integration

Run `supabase/migrations/02_clerk_native_integration.sql`:

This adds:
- `auth.clerk_user_id()` helper function
- `auth.clerk_org_id()` helper function
- Updated RLS policies using native Clerk functions
- Advisory lock functions for credential injection
- Updated Vault functions for supabase_vault
- Profile sync function for webhooks

### Verify Migrations

```sql
-- Check helper functions exist
SELECT auth.clerk_user_id();
SELECT auth.clerk_org_id();

-- Check tables
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public';

-- Check RLS is enabled
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public';
```

## 4. Configure Vault for Credentials

Supabase Vault stores encrypted tenant credentials:

```sql
-- Store credentials (done via RPC from the gateway)
SELECT private.store_tenant_credentials(
    'org-uuid-12345',
    '{"openai": {"api_key": "sk-xxx"}, "slack": {"access_token": "xoxb-xxx"}}'
);

-- Retrieve credentials (only service role can do this)
SELECT private.get_tenant_credentials('org-uuid-12345');
```

## 5. API Keys and Configuration

Get your API keys from Supabase Dashboard → Settings → API:

```bash
# .env file
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Security Notes:**
- `anon_key`: Safe for client-side, respects RLS
- `service_role_key`: NEVER expose client-side, bypasses RLS

## 6. Row Level Security (RLS) Overview

### How It Works with Clerk

The native integration sets JWT claims in the request context:

```sql
-- Clerk user ID from JWT
auth.clerk_user_id() -- Returns 'user_xxxxx'

-- Clerk organization ID from JWT
auth.clerk_org_id() -- Returns 'org_xxxxx' or NULL
```

### Policy Examples

```sql
-- Users can only read their own profile
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (id = auth.clerk_user_id());

-- Members can read their organization's data
CREATE POLICY "org_data_select" ON some_table
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = some_table.organization_id
            AND profile_id = auth.clerk_user_id()
        )
    );
```

## 7. Testing the Integration

### Test Profile Creation

```sql
-- Insert a test profile
INSERT INTO profiles (id, email, name) 
VALUES ('user_test123', 'test@example.com', 'Test User');

-- Verify RLS (should fail without proper JWT)
SET request.jwt.claims = '{"sub": "user_test123"}';
SELECT * FROM profiles;  -- Should return the test user
```

### Test Organization Flow

```sql
-- Create test organization
INSERT INTO organizations (name, owner_id, tenant_id, api_key_hash, api_key_prefix, credits)
VALUES ('Test Org', 'user_test123', 'test-tenant', 'hash', 'gw_live_', 100);

-- The trigger should auto-create membership
SELECT * FROM organization_members WHERE profile_id = 'user_test123';
```

## 8. Webhook Configuration (Optional)

To sync users from Clerk automatically:

### In Clerk Dashboard:

1. Go to **Webhooks**
2. Create a new webhook endpoint:
   - URL: `https://your-gateway.com/api/v1/webhooks/clerk`
   - Events: `user.created`, `user.updated`, `user.deleted`
3. Copy the signing secret

### In Gateway:

```bash
# Add to .env
CLERK_WEBHOOK_SECRET=whsec_xxxxx
```

## 9. Troubleshooting

### Common Issues

**"Invalid input syntax for type uuid"**
- Cause: Trying to use Clerk user ID (text) in UUID column
- Solution: Ensure `profiles.id` is TEXT type, not UUID

**"Permission denied for table"**
- Cause: RLS blocking access
- Solution: Check JWT claims are being set correctly

**"Function auth.clerk_user_id() does not exist"**
- Cause: Migration not applied
- Solution: Run migration 02_clerk_native_integration.sql

### Debug Queries

```sql
-- Check current user context
SELECT 
    current_setting('request.jwt.claims', true) as claims,
    auth.clerk_user_id() as user_id,
    auth.clerk_org_id() as org_id;

-- Check if user has access to organization
SELECT EXISTS (
    SELECT 1 FROM organization_members
    WHERE profile_id = auth.clerk_user_id()
    AND organization_id = 'org-uuid'
);
```

## 10. Production Checklist

- [ ] All migrations applied
- [ ] RLS enabled on all tables
- [ ] Service role key secured
- [ ] Vault configured for credentials
- [ ] Backup strategy in place
- [ ] Connection pooling configured
- [ ] Database password rotated from default
- [ ] SSL enforced for connections
