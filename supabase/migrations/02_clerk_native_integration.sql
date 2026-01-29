-- =============================================================================
-- N8N ORCHESTRATION GATEWAY - CLERK NATIVE INTEGRATION
-- =============================================================================
-- This migration updates the schema for Clerk's native Supabase integration.
-- 
-- Key Changes:
-- 1. Creates auth.clerk_user_id() helper function for RLS policies
-- 2. Creates auth.clerk_org_id() helper function for organization context
-- 3. Updates RLS policies to use native Clerk JWT claims
-- 4. Adds advisory lock functions for credential injection
-- 5. Updates vault functions for secure credential management
-- =============================================================================

-- =============================================================================
-- CLERK HELPER FUNCTIONS
-- =============================================================================
-- These functions extract claims from the Clerk JWT token set by the
-- Supabase-Clerk native integration.

-- Helper function to get the authenticated Clerk user ID
CREATE OR REPLACE FUNCTION auth.clerk_user_id()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    -- Native Clerk integration sets JWT claims in request settings
    SELECT COALESCE(
        -- Try native Clerk integration format
        nullif(current_setting('request.jwt.claims', true), '')::json->>'sub',
        -- Fallback to auth.uid() cast for backward compatibility
        (auth.uid())::TEXT
    );
$$;

COMMENT ON FUNCTION auth.clerk_user_id() IS 
    'Returns the Clerk user ID (sub claim) from the JWT token. Compatible with native Clerk-Supabase integration.';


-- Helper function to get the authenticated Clerk organization ID
CREATE OR REPLACE FUNCTION auth.clerk_org_id()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT nullif(current_setting('request.jwt.claims', true), '')::json->>'org_id';
$$;

COMMENT ON FUNCTION auth.clerk_org_id() IS 
    'Returns the Clerk organization ID (org_id claim) from the JWT token.';


-- Helper function to get the user's organization role
CREATE OR REPLACE FUNCTION auth.clerk_org_role()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT nullif(current_setting('request.jwt.claims', true), '')::json->>'org_role';
$$;

COMMENT ON FUNCTION auth.clerk_org_role() IS 
    'Returns the user role within the Clerk organization (org_role claim).';


-- Helper to check if user is authenticated
CREATE OR REPLACE FUNCTION auth.is_authenticated()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT auth.clerk_user_id() IS NOT NULL;
$$;


-- =============================================================================
-- DROP EXISTING RLS POLICIES (to recreate with Clerk functions)
-- =============================================================================

-- Profiles policies
DROP POLICY IF EXISTS "profiles_select_own" ON profiles;
DROP POLICY IF EXISTS "profiles_update_own" ON profiles;
DROP POLICY IF EXISTS "profiles_service_role" ON profiles;

-- Organizations policies
DROP POLICY IF EXISTS "organizations_select_member" ON organizations;
DROP POLICY IF EXISTS "organizations_update_admin" ON organizations;
DROP POLICY IF EXISTS "organizations_service_role" ON organizations;

-- Organization members policies
DROP POLICY IF EXISTS "org_members_select" ON organization_members;
DROP POLICY IF EXISTS "org_members_admin" ON organization_members;
DROP POLICY IF EXISTS "org_members_service_role" ON organization_members;

-- Workflows policies
DROP POLICY IF EXISTS "workflows_select_member" ON workflows;
DROP POLICY IF EXISTS "workflows_admin" ON workflows;
DROP POLICY IF EXISTS "workflows_service_role" ON workflows;

-- Usage logs policies
DROP POLICY IF EXISTS "usage_logs_select_member" ON usage_logs;
DROP POLICY IF EXISTS "usage_logs_service_role" ON usage_logs;

-- Invoices policies
DROP POLICY IF EXISTS "invoices_select_member" ON invoices;
DROP POLICY IF EXISTS "invoices_service_role" ON invoices;

-- Security logs policies
DROP POLICY IF EXISTS "security_logs_select_admin" ON security_logs;
DROP POLICY IF EXISTS "security_logs_service_role" ON security_logs;

-- API keys policies
DROP POLICY IF EXISTS "api_keys_admin" ON api_keys;
DROP POLICY IF EXISTS "api_keys_service_role" ON api_keys;


-- =============================================================================
-- RECREATE RLS POLICIES WITH CLERK NATIVE FUNCTIONS
-- =============================================================================

-- -----------------------------------------------------------------------------
-- PROFILES POLICIES
-- -----------------------------------------------------------------------------

-- Users can read their own profile (using Clerk user ID)
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (id = auth.clerk_user_id());

-- Users can update their own profile
CREATE POLICY "profiles_update_own" ON profiles
    FOR UPDATE
    USING (id = auth.clerk_user_id())
    WITH CHECK (id = auth.clerk_user_id());

-- Service role can manage all profiles
CREATE POLICY "profiles_service_role" ON profiles
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- ORGANIZATIONS POLICIES
-- -----------------------------------------------------------------------------

-- Members can read their organizations
CREATE POLICY "organizations_select_member" ON organizations
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.clerk_user_id()
        )
    );

-- Owners and admins can update their organizations
CREATE POLICY "organizations_update_admin" ON organizations
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.clerk_user_id()
            AND role IN ('owner', 'admin')
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.clerk_user_id()
            AND role IN ('owner', 'admin')
        )
    );

-- Service role can manage all organizations
CREATE POLICY "organizations_service_role" ON organizations
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- ORGANIZATION MEMBERS POLICIES
-- -----------------------------------------------------------------------------

-- Members can see other members in their org
CREATE POLICY "org_members_select" ON organization_members
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.organization_id = organization_members.organization_id
            AND om.profile_id = auth.clerk_user_id()
        )
    );

-- Owners and admins can manage members
CREATE POLICY "org_members_admin" ON organization_members
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.organization_id = organization_members.organization_id
            AND om.profile_id = auth.clerk_user_id()
            AND om.role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "org_members_service_role" ON organization_members
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- WORKFLOWS POLICIES
-- -----------------------------------------------------------------------------

-- Members can read workflows
CREATE POLICY "workflows_select_member" ON workflows
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = auth.clerk_user_id()
        )
    );

-- Admins can manage workflows
CREATE POLICY "workflows_admin" ON workflows
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = auth.clerk_user_id()
            AND role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "workflows_service_role" ON workflows
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- USAGE LOGS POLICIES
-- -----------------------------------------------------------------------------

-- Members can read their org's usage logs
CREATE POLICY "usage_logs_select_member" ON usage_logs
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = usage_logs.organization_id
            AND profile_id = auth.clerk_user_id()
        )
    );

-- Only service role can insert/update usage logs
CREATE POLICY "usage_logs_service_role" ON usage_logs
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- INVOICES POLICIES
-- -----------------------------------------------------------------------------

-- Members can read their org's invoices
CREATE POLICY "invoices_select_member" ON invoices
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = invoices.organization_id
            AND profile_id = auth.clerk_user_id()
        )
    );

-- Service role manages invoices
CREATE POLICY "invoices_service_role" ON invoices
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- SECURITY LOGS POLICIES
-- -----------------------------------------------------------------------------

-- Admins can read security logs
CREATE POLICY "security_logs_select_admin" ON security_logs
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = security_logs.organization_id
            AND profile_id = auth.clerk_user_id()
            AND role IN ('owner', 'admin')
        )
    );

-- Service role manages security logs
CREATE POLICY "security_logs_service_role" ON security_logs
    FOR ALL
    USING (auth.role() = 'service_role');


-- -----------------------------------------------------------------------------
-- API KEYS POLICIES
-- -----------------------------------------------------------------------------

-- Admins can manage API keys
CREATE POLICY "api_keys_admin" ON api_keys
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = api_keys.organization_id
            AND profile_id = auth.clerk_user_id()
            AND role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "api_keys_service_role" ON api_keys
    FOR ALL
    USING (auth.role() = 'service_role');


-- =============================================================================
-- N8N CREDENTIAL INJECTION - ADVISORY LOCKS
-- =============================================================================
-- These functions implement the "Static Identity / Dynamic Data" pattern
-- for secure credential injection into n8n workflows.

-- Table to track n8n base credential IDs per service type
CREATE TABLE IF NOT EXISTS n8n_base_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_type TEXT NOT NULL UNIQUE,  -- e.g., 'openai', 'slack', 'hubspot'
    n8n_credential_id TEXT NOT NULL,     -- The credential ID in n8n
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

COMMENT ON TABLE n8n_base_credentials IS 
    'Maps service types to their base credential IDs in n8n. These are the "static identity" credentials that get dynamically updated with tenant data.';

CREATE INDEX idx_n8n_base_credentials_service ON n8n_base_credentials(service_type);


-- Function to acquire advisory lock for credential updates
-- Uses org_id hash as lock key to serialize updates per tenant
CREATE OR REPLACE FUNCTION fn_acquire_credential_lock(
    p_org_id UUID,
    p_timeout_ms INTEGER DEFAULT 5000
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_lock_key BIGINT;
    v_acquired BOOLEAN;
BEGIN
    -- Generate a consistent lock key from org_id
    -- Using hashtext to convert UUID to a bigint for pg_advisory_xact_lock
    v_lock_key := ('x' || substr(md5(p_org_id::TEXT), 1, 16))::bit(64)::bigint;
    
    -- Try to acquire the lock with timeout
    -- pg_advisory_xact_lock_shared allows concurrent reads but exclusive writes
    BEGIN
        -- Use statement_timeout to implement timeout
        EXECUTE format('SET LOCAL statement_timeout = %L', p_timeout_ms || 'ms');
        
        -- Acquire transaction-level exclusive lock
        PERFORM pg_advisory_xact_lock(v_lock_key);
        
        -- Reset timeout
        RESET statement_timeout;
        
        RETURN TRUE;
    EXCEPTION 
        WHEN query_canceled THEN
            -- Timeout occurred
            RESET statement_timeout;
            RETURN FALSE;
        WHEN OTHERS THEN
            RESET statement_timeout;
            RAISE;
    END;
END;
$$;

COMMENT ON FUNCTION fn_acquire_credential_lock(UUID, INTEGER) IS 
    'Acquires a transaction-level advisory lock for credential updates. Prevents credential bleed between concurrent requests for the same tenant.';


-- Function to get tenant credentials with lock
CREATE OR REPLACE FUNCTION fn_get_credentials_with_lock(
    p_org_id UUID,
    p_service_types TEXT[] DEFAULT NULL
) RETURNS TABLE (
    service_type TEXT,
    credentials JSONB,
    n8n_credential_id TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_lock_acquired BOOLEAN;
BEGIN
    -- First acquire the lock
    v_lock_acquired := fn_acquire_credential_lock(p_org_id);
    
    IF NOT v_lock_acquired THEN
        RAISE EXCEPTION 'Failed to acquire credential lock for org %', p_org_id;
    END IF;
    
    -- Return credentials from vault with base credential IDs
    RETURN QUERY
    SELECT 
        nbc.service_type,
        private.get_tenant_credentials(p_org_id) AS credentials,
        nbc.n8n_credential_id
    FROM n8n_base_credentials nbc
    WHERE nbc.is_active = TRUE
    AND (p_service_types IS NULL OR nbc.service_type = ANY(p_service_types));
END;
$$;

COMMENT ON FUNCTION fn_get_credentials_with_lock(UUID, TEXT[]) IS 
    'Retrieves tenant credentials from vault with an advisory lock held. The lock is released when the transaction commits or rolls back.';


-- =============================================================================
-- UPDATED VAULT FUNCTIONS FOR SUPABASE_VAULT
-- =============================================================================
-- Updated to use supabase_vault extension (the new name for vault)

-- Function to store tenant credentials in Supabase Vault
CREATE OR REPLACE FUNCTION private.store_tenant_credentials(
    p_org_id UUID,
    p_credentials JSONB
) RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, supabase_vault, vault
AS $$
DECLARE
    v_secret_id UUID;
    v_secret_name TEXT;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    -- Check if secret already exists and delete it
    -- Try supabase_vault schema first, fall back to vault
    BEGIN
        DELETE FROM vault.secrets WHERE name = v_secret_name;
    EXCEPTION WHEN undefined_table THEN
        -- Try supabase_vault schema
        DELETE FROM supabase_vault.secrets WHERE name = v_secret_name;
    END;
    
    -- Insert new secret
    BEGIN
        INSERT INTO vault.secrets (name, secret, description)
        VALUES (
            v_secret_name,
            p_credentials::TEXT,
            'Encrypted credentials for tenant ' || p_org_id::TEXT
        )
        RETURNING id INTO v_secret_id;
    EXCEPTION WHEN undefined_table THEN
        -- Try supabase_vault schema
        INSERT INTO supabase_vault.secrets (name, secret, description)
        VALUES (
            v_secret_name,
            p_credentials::TEXT,
            'Encrypted credentials for tenant ' || p_org_id::TEXT
        )
        RETURNING id INTO v_secret_id;
    END;
    
    RETURN v_secret_id;
END;
$$;


-- Function to retrieve tenant credentials from vault
CREATE OR REPLACE FUNCTION private.get_tenant_credentials(
    p_org_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, supabase_vault, vault
AS $$
DECLARE
    v_secret_name TEXT;
    v_credentials TEXT;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    -- Try vault schema first
    BEGIN
        SELECT decrypted_secret INTO v_credentials
        FROM vault.decrypted_secrets
        WHERE name = v_secret_name;
    EXCEPTION WHEN undefined_table THEN
        -- Try supabase_vault schema
        SELECT decrypted_secret INTO v_credentials
        FROM supabase_vault.decrypted_secrets
        WHERE name = v_secret_name;
    END;
    
    IF v_credentials IS NULL THEN
        RETURN NULL;
    END IF;
    
    RETURN v_credentials::JSONB;
END;
$$;


-- Function to delete tenant credentials from vault
CREATE OR REPLACE FUNCTION private.delete_tenant_credentials(
    p_org_id UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, supabase_vault, vault
AS $$
DECLARE
    v_secret_name TEXT;
    v_deleted INTEGER;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    -- Try vault schema first
    BEGIN
        DELETE FROM vault.secrets WHERE name = v_secret_name;
        GET DIAGNOSTICS v_deleted = ROW_COUNT;
    EXCEPTION WHEN undefined_table THEN
        -- Try supabase_vault schema
        DELETE FROM supabase_vault.secrets WHERE name = v_secret_name;
        GET DIAGNOSTICS v_deleted = ROW_COUNT;
    END;
    
    RETURN v_deleted > 0;
END;
$$;


-- =============================================================================
-- PROFILE SYNC FUNCTION FOR CLERK WEBHOOKS
-- =============================================================================
-- This function is called by the webhook handler when Clerk sends user updates

CREATE OR REPLACE FUNCTION fn_sync_clerk_user(
    p_user_id TEXT,
    p_email TEXT,
    p_name TEXT DEFAULT NULL,
    p_username TEXT DEFAULT NULL,
    p_avatar_url TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::JSONB
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_profile_id TEXT;
BEGIN
    INSERT INTO profiles (
        id,
        email,
        name,
        username,
        avatar_url,
        metadata,
        email_verified
    ) VALUES (
        p_user_id,
        p_email,
        p_name,
        p_username,
        p_avatar_url,
        p_metadata,
        TRUE  -- Clerk verifies emails
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = COALESCE(EXCLUDED.name, profiles.name),
        username = COALESCE(EXCLUDED.username, profiles.username),
        avatar_url = COALESCE(EXCLUDED.avatar_url, profiles.avatar_url),
        metadata = profiles.metadata || EXCLUDED.metadata,
        updated_at = NOW()
    RETURNING id INTO v_profile_id;
    
    -- Return the TEXT profile ID (Clerk user IDs are strings like 'user_xxxx')
    RETURN v_profile_id;
END;
$$;

COMMENT ON FUNCTION fn_sync_clerk_user IS 
    'Syncs user profile data from Clerk webhooks. Called when user.created or user.updated events are received.';


-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant execute on new functions to authenticated users
GRANT EXECUTE ON FUNCTION auth.clerk_user_id TO authenticated;
GRANT EXECUTE ON FUNCTION auth.clerk_org_id TO authenticated;
GRANT EXECUTE ON FUNCTION auth.clerk_org_role TO authenticated;
GRANT EXECUTE ON FUNCTION auth.is_authenticated TO authenticated;
GRANT EXECUTE ON FUNCTION fn_acquire_credential_lock TO service_role;
GRANT EXECUTE ON FUNCTION fn_get_credentials_with_lock TO service_role;
GRANT EXECUTE ON FUNCTION fn_sync_clerk_user TO service_role;

-- Grant access to n8n_base_credentials table
GRANT SELECT ON n8n_base_credentials TO authenticated;
GRANT ALL ON n8n_base_credentials TO service_role;


-- =============================================================================
-- UPDATED TRIGGER FOR n8n_base_credentials
-- =============================================================================

CREATE TRIGGER update_n8n_base_credentials_updated_at
    BEFORE UPDATE ON n8n_base_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
