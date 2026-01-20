-- Production-grade initial schema for the orchestration gateway
-- Extensions
create extension if not exists "pgcrypto";
create extension if not exists "citext";
create extension if not exists "vault";

-- Private schema for sensitive mapping data
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to postgres, service_role;

-- Profiles (Clerk UID is the primary key)
create table if not exists public.profiles (
    id text primary key,
    name text,
    username text,
    email citext,
    verified_status boolean not null default false,
    phone text,
    company_name text,
    created_at timestamptz not null default now()
);

-- Organizations (multi-tenant)
create table if not exists public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_id text not null references public.profiles(id) on delete cascade,
    tenant_id text not null unique,
    api_key_hash text,
    credits integer not null default 0,
    plan_type text not null default 'free',
    created_at timestamptz not null default now()
);

create index if not exists organizations_owner_id_idx on public.organizations(owner_id);
create index if not exists organizations_tenant_id_idx on public.organizations(tenant_id);

-- Workflows
create table if not exists public.workflows (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references public.organizations(id) on delete cascade,
    n8n_workflow_id text not null,
    is_active boolean not null default true,
    created_at timestamptz not null default now()
);

create index if not exists workflows_org_id_idx on public.workflows(org_id);

-- Usage logs
create table if not exists public.usage_logs (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references public.organizations(id) on delete cascade,
    credits_used integer not null,
    status text not null,
    metadata jsonb not null default '{}'::jsonb,
    "timestamp" timestamptz not null default now()
);

create index if not exists usage_logs_org_id_idx on public.usage_logs(org_id);

-- Invoices
create table if not exists public.invoices (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references public.organizations(id) on delete cascade,
    amount numeric(12, 2) not null,
    status text not null,
    billing_date date not null,
    created_at timestamptz not null default now()
);

create index if not exists invoices_org_id_idx on public.invoices(org_id);

-- Security logs
create table if not exists public.security_logs (
    id uuid primary key default gen_random_uuid(),
    org_id uuid references public.organizations(id) on delete cascade,
    user_id text,
    fingerprint_hash text not null,
    status text not null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists security_logs_org_id_idx on public.security_logs(org_id);
create index if not exists security_logs_user_id_idx on public.security_logs(user_id);

-- Tenant credentials map to Supabase Vault secrets (no raw keys in public schema)
create table if not exists private.tenant_credentials (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references public.organizations(id) on delete cascade,
    vault_secret_id uuid not null,
    created_at timestamptz not null default now()
);

create index if not exists tenant_credentials_org_id_idx on private.tenant_credentials(org_id);

-- RLS policies
alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.workflows enable row level security;
alter table public.usage_logs enable row level security;
alter table public.invoices enable row level security;
alter table public.security_logs enable row level security;
alter table private.tenant_credentials enable row level security;

create policy "Profiles are self readable"
    on public.profiles for select
    using (id = auth.uid());

create policy "Profiles are self insertable"
    on public.profiles for insert
    with check (id = auth.uid());

create policy "Profiles are self updatable"
    on public.profiles for update
    using (id = auth.uid())
    with check (id = auth.uid());

create policy "Organizations are owned by user"
    on public.organizations for select
    using (owner_id = auth.uid());

create policy "Organizations insert by owner"
    on public.organizations for insert
    with check (owner_id = auth.uid());

create policy "Organizations update by owner"
    on public.organizations for update
    using (owner_id = auth.uid())
    with check (owner_id = auth.uid());

create policy "Organizations delete by owner"
    on public.organizations for delete
    using (owner_id = auth.uid());

create policy "Workflows read by org owner"
    on public.workflows for select
    using (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Workflows write by org owner"
    on public.workflows for insert
    with check (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Usage logs read by org owner"
    on public.usage_logs for select
    using (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Usage logs insert by org owner"
    on public.usage_logs for insert
    with check (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Invoices read by org owner"
    on public.invoices for select
    using (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Invoices write by org owner"
    on public.invoices for insert
    with check (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Security logs read by org owner"
    on public.security_logs for select
    using (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

create policy "Security logs insert by org owner"
    on public.security_logs for insert
    with check (
        exists (
            select 1 from public.organizations o
            where o.id = org_id and o.owner_id = auth.uid()
        )
    );

-- No policies on private.tenant_credentials (service_role only)

-- RPC: Deduct credits atomically and log usage
create or replace function public.fn_deduct_credits(
    p_org_id uuid,
    p_credits integer,
    p_status text default 'charged',
    p_metadata jsonb default '{}'::jsonb
)
returns integer
language plpgsql
security definer
set search_path = public, private, vault
as $$
declare
    v_owner_id text;
    v_new_credits integer;
begin
    if p_credits <= 0 then
        raise exception 'credits must be positive';
    end if;

    select owner_id into v_owner_id from public.organizations where id = p_org_id;
    if v_owner_id is null then
        raise exception 'organization not found';
    end if;

    if current_setting('request.jwt.claim.role', true) <> 'service_role' then
        if auth.uid() is null or auth.uid() <> v_owner_id then
            raise exception 'not authorized';
        end if;
    end if;

    update public.organizations
        set credits = credits - p_credits
        where id = p_org_id and credits >= p_credits
        returning credits into v_new_credits;

    if v_new_credits is null then
        raise exception 'insufficient credits';
    end if;

    insert into public.usage_logs (org_id, credits_used, status, metadata)
    values (p_org_id, p_credits, p_status, p_metadata);

    return v_new_credits;
end;
$$;

grant execute on function public.fn_deduct_credits(uuid, integer, text, jsonb)
    to authenticated, service_role;

-- RPC: Read tenant secrets from Supabase Vault
create or replace function public.fn_get_tenant_secrets(
    p_org_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, private, vault
as $$
declare
    v_owner_id text;
    v_secret_id uuid;
    v_secret_text text;
begin
    select owner_id into v_owner_id from public.organizations where id = p_org_id;
    if v_owner_id is null then
        raise exception 'organization not found';
    end if;

    if current_setting('request.jwt.claim.role', true) <> 'service_role' then
        if auth.uid() is null or auth.uid() <> v_owner_id then
            raise exception 'not authorized';
        end if;
    end if;

    select vault_secret_id into v_secret_id
    from private.tenant_credentials
    where org_id = p_org_id;

    if v_secret_id is null then
        raise exception 'tenant secrets not configured';
    end if;

    select vault.read_secret(v_secret_id) into v_secret_text;
    return v_secret_text::jsonb;
end;
$$;

grant execute on function public.fn_get_tenant_secrets(uuid)
    to authenticated, service_role;
