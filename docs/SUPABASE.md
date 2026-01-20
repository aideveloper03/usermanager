# Supabase Setup

This gateway uses Supabase PostgreSQL with RLS and Supabase Vault for tenant secrets.

## 1) Enable Extensions

The migration enables the required extensions:

- `pgcrypto` (UUID + hashing)
- `citext` (case-insensitive emails)
- `vault` (secret storage)

Apply the migration:

```bash
supabase db reset
# or
psql "$SUPABASE_DB_URL" -f supabase/migrations/01_initial_schema.sql
```

## 2) Configure Clerk Third-Party Auth

In the Supabase dashboard:

1. **Auth → Settings → JWT**:
   - Set the JWT issuer to your Clerk issuer.
   - Set the JWT audience to match the Clerk audience (if configured).
2. **Auth → Third-Party Auth**:
   - Add Clerk and set the JWKS URL (same value as `CLERK_JWKS_URL`).

This allows Supabase to treat Clerk JWTs as authenticated sessions, and `auth.uid()`
will match the Clerk `sub` (user ID).

## 3) Seed Profiles & Organizations

Insert a profile for each Clerk user:

```sql
insert into public.profiles (id, name, email, verified_status)
values ('user_123', 'Jane Doe', 'jane@example.com', true);
```

Create an organization:

```sql
insert into public.organizations (name, owner_id, tenant_id, credits, plan_type)
values ('Acme Corp', 'user_123', 'tenant_acme', 1000, 'pro');
```

## 4) Store Tenant Secrets in Vault

Store a JSON object of secrets per tenant. The `client_secret` is used for HMAC.

```sql
select vault.create_secret(
  'tenant_acme',
  '{"client_secret": "super-secret", "n8n_api_key": "n8n-secret"}'
);
```

Capture the returned UUID and insert it into `private.tenant_credentials`:

```sql
insert into private.tenant_credentials (org_id, vault_secret_id)
values (
  (select id from public.organizations where tenant_id = 'tenant_acme'),
  '<vault_secret_uuid>'
);
```

## 5) Credits & Usage Logs

Credits are deducted via the RPC function `fn_deduct_credits`. It logs into
`usage_logs` atomically to prevent race conditions.

Example RPC call:

```sql
select public.fn_deduct_credits(
  (select id from public.organizations where tenant_id = 'tenant_acme'),
  1,
  'charged',
  '{"source": "execute"}'
);
```

## 6) RLS Overview

RLS policies enforce per-user isolation on:

- profiles
- organizations
- workflows
- usage_logs
- invoices
- security_logs

The `private.tenant_credentials` table has RLS enabled without policies, so only
the service role can access it.
