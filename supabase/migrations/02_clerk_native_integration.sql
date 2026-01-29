-- =============================================================================
-- N8N ORCHESTRATION GATEWAY - CLERK NATIVE SUPABASE INTEGRATION
-- =============================================================================
-- This migration updates the schema for Clerk's native Supabase integration.
-- 
-- Integration Setup:
-- 1. In Clerk Dashboard: Enable Supabase integration to get Clerk domain
-- 2. In Supabase Dashboard: Add Clerk as third-party auth provider
-- 
-- Key Changes:
-- 1. Uses auth.jwt()->>'sub' for Clerk user ID (native integration)
-- 2. Uses auth.jwt()->>'org_id' for organization context
-- 3. RLS policies use native JWT claims
-- 4. Compatible with Clerk's "role": "authenticated" claim
-- =============================================================================

-- =============================================================================
-- CLERK HELPER FUNCTIONS
-- =============================================================================
-- These functions extract claims from the Clerk JWT token set by the
-- Supabase-Clerk native integration.

-- Helper function to get the authenticated Clerk user ID
-- Uses the 'sub' claim from the JWT which contains the Clerk user ID
CREATE OR REPLACE FUNCTION auth.clerk_user_id()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        -- Native Clerk integration: get 'sub' claim from JWT
        (auth.jwt()->>'sub'),
        -- Fallback to auth.uid() for backward compatibility
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
    SELECT auth.jwt()->>'org_id';
$$;

COMMENT ON FUNCTION auth.clerk_org_id() IS 
    'Returns the Clerk organization ID (org_id claim) from the JWT token.';


-- Helper function to get the user's organization role
CREATE OR REPLACE FUNCTION auth.clerk_org_role()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT auth.jwt()->>'org_role';
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

COMMENT ON FUNCTION auth.is_authenticated() IS 
    'Returns true if the request has a valid authenticated user.';


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
-- RECREATE RLS POLICIES WITH CLERK NATIVE INTEGRATION
-- =============================================================================
-- These policies use auth.jwt()->>'sub' for the Clerk user ID which is the
-- standard pattern for Clerk's native Supabase integration.

-- -----------------------------------------------------------------------------
-- PROFILES POLICIES
-- -----------------------------------------------------------------------------

-- Users can read their own profile (using Clerk user ID from JWT)
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (id = (auth.jwt()->>'sub'));

-- Users can update their own profile
CREATE POLICY "profiles_update_own" ON profiles
    FOR UPDATE
    USING (id = (auth.jwt()->>'sub'))
    WITH CHECK (id = (auth.jwt()->>'sub'));

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
            AND profile_id = (auth.jwt()->>'sub')
        )
    );

-- Owners and admins can update their organizations
CREATE POLICY "organizations_update_admin" ON organizations
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = (auth.jwt()->>'sub')
            AND role IN ('owner', 'admin')
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = (auth.jwt()->>'sub')
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
            AND om.profile_id = (auth.jwt()->>'sub')
        )
    );

-- Owners and admins can manage members
CREATE POLICY "org_members_admin" ON organization_members
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.organization_id = organization_members.organization_id
            AND om.profile_id = (auth.jwt()->>'sub')
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
            AND profile_id = (auth.jwt()->>'sub')
        )
    );

-- Admins can manage workflows
CREATE POLICY "workflows_admin" ON workflows
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = (auth.jwt()->>'sub')
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
            AND profile_id = (auth.jwt()->>'sub')
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
            AND profile_id = (auth.jwt()->>'sub')
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
            AND profile_id = (auth.jwt()->>'sub')
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
            AND profile_id = (auth.jwt()->>'sub')
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

CREATE INDEX IF NOT EXISTS idx_n8n_base_credentials_service ON n8n_base_credentials(service_type);


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
BEGIN
    -- Generate a consistent lock key from org_id
    v_lock_key := ('x' || substr(md5(p_org_id::TEXT), 1, 16))::bit(64)::bigint;
    
    -- Try to acquire the lock with timeout
    BEGIN
        EXECUTE format('SET LOCAL statement_timeout = %L', p_timeout_ms || 'ms');
        PERFORM pg_advisory_xact_lock(v_lock_key);
        RESET statement_timeout;
        RETURN TRUE;
    EXCEPTION 
        WHEN query_canceled THEN
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
    
    RETURN v_profile_id;
END;
$$;

COMMENT ON FUNCTION fn_sync_clerk_user IS 
    'Syncs user profile data from Clerk webhooks. Called when user.created or user.updated events are received.';


-- =============================================================================
-- UPDATED TRIGGER FOR n8n_base_credentials
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_n8n_base_credentials_updated_at'
    ) THEN
        CREATE TRIGGER update_n8n_base_credentials_updated_at
            BEFORE UPDATE ON n8n_base_credentials
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;


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
