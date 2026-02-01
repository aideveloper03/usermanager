-- =============================================================================
-- N8N ORCHESTRATION GATEWAY - CLERK THIRD-PARTY AUTH PROVIDER SETUP
-- =============================================================================
-- This migration documents the Supabase configuration required for native
-- Clerk integration. These SQL statements are for reference - the actual
-- third-party auth provider must be configured via:
--
-- 1. Supabase Dashboard: Authentication → Providers → Third-party Auth
-- 2. OR Supabase CLI: supabase auth add-provider
--
-- ARCHITECTURE OVERVIEW:
-- ----------------------
-- Clerk JWTs are passed directly to Supabase, which validates them using
-- Clerk's JWKS endpoint. The JWT claims become available in RLS policies
-- via auth.jwt() function.
--
-- JWT Claims Mapping:
--   - auth.jwt()->>'sub'     : Clerk User ID (user_xxx)
--   - auth.jwt()->>'org_id'  : Clerk Organization ID (org_xxx)
--   - auth.jwt()->>'org_role': User's role in the organization
--   - auth.jwt()->>'email'   : User's email address
--
-- SETUP INSTRUCTIONS:
-- -------------------
-- 1. In Clerk Dashboard:
--    - Go to Integrations → Supabase
--    - Copy the Clerk JWT issuer URL (e.g., https://xxx.clerk.accounts.dev)
--
-- 2. In Supabase Dashboard:
--    - Go to Authentication → Providers
--    - Enable "Third-party Auth Provider"
--    - Set "Auth Provider" to "Clerk"
--    - Enter your Clerk JWKS URL:
--      https://YOUR_CLERK_FRONTEND_API/.well-known/jwks.json
--    - Set "JWT Issuer" to your Clerk issuer URL
--
-- 3. In your application:
--    - Pass Clerk session token as Authorization: Bearer <token>
--    - Supabase validates the JWT and enforces RLS policies
-- =============================================================================

-- =============================================================================
-- ADDITIONAL HELPER FUNCTIONS FOR CLERK CLAIMS
-- =============================================================================

-- Get email from Clerk JWT
CREATE OR REPLACE FUNCTION auth.clerk_email()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT auth.jwt()->>'email';
$$;

COMMENT ON FUNCTION auth.clerk_email() IS 
    'Returns the email address from the Clerk JWT token.';


-- Get session ID from Clerk JWT
CREATE OR REPLACE FUNCTION auth.clerk_session_id()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT auth.jwt()->>'sid';
$$;

COMMENT ON FUNCTION auth.clerk_session_id() IS 
    'Returns the Clerk session ID (sid claim) from the JWT token.';


-- Check if user has specific org role
CREATE OR REPLACE FUNCTION auth.clerk_has_org_role(required_role TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT auth.clerk_org_role() = required_role;
$$;

COMMENT ON FUNCTION auth.clerk_has_org_role(TEXT) IS 
    'Returns true if the authenticated user has the specified organization role.';


-- Check if user is org admin or owner
CREATE OR REPLACE FUNCTION auth.clerk_is_org_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT auth.clerk_org_role() IN ('admin', 'owner', 'org:admin');
$$;

COMMENT ON FUNCTION auth.clerk_is_org_admin() IS 
    'Returns true if the authenticated user is an admin or owner of the organization.';


-- =============================================================================
-- AUTHENTICATED USER POLICIES (Alternative to service_role bypass)
-- =============================================================================
-- These policies allow authenticated Clerk users to access data they own
-- or are members of, without requiring service_role access.

-- Enable authenticated users to insert their own profile (on first login)
CREATE POLICY IF NOT EXISTS "profiles_insert_own" ON profiles
    FOR INSERT
    TO authenticated
    WITH CHECK (id = (auth.jwt()->>'sub'));


-- =============================================================================
-- TENANT CREDENTIAL STORAGE - ENHANCED SECURITY
-- =============================================================================

-- Create a mapping table for service credentials (links org to n8n credential IDs)
CREATE TABLE IF NOT EXISTS tenant_credential_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL,  -- e.g., 'openai', 'slack', 'hubspot'
    n8n_credential_id TEXT NOT NULL,  -- The credential ID in n8n
    is_active BOOLEAN DEFAULT TRUE,
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    UNIQUE(organization_id, service_type)
);

CREATE INDEX IF NOT EXISTS idx_tenant_cred_mappings_org ON tenant_credential_mappings(organization_id);
CREATE INDEX IF NOT EXISTS idx_tenant_cred_mappings_service ON tenant_credential_mappings(service_type);

-- Enable RLS on credential mappings
ALTER TABLE tenant_credential_mappings ENABLE ROW LEVEL SECURITY;

-- Only service role can manage credential mappings
CREATE POLICY "tenant_cred_mappings_service_role" ON tenant_credential_mappings
    FOR ALL
    USING (auth.role() = 'service_role');

-- Add trigger for updated_at
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_tenant_cred_mappings_updated_at'
    ) THEN
        CREATE TRIGGER update_tenant_cred_mappings_updated_at
            BEFORE UPDATE ON tenant_credential_mappings
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

COMMENT ON TABLE tenant_credential_mappings IS 
    'Maps tenant organizations to their n8n credential IDs for each service type. Used for dynamic credential injection.';


-- =============================================================================
-- ENHANCED CREDENTIAL RETRIEVAL WITH MAPPINGS
-- =============================================================================

-- Drop and recreate the credential retrieval function to include mappings
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
    v_raw_credentials JSONB;
BEGIN
    -- First acquire the advisory lock
    v_lock_acquired := fn_acquire_credential_lock(p_org_id);
    
    IF NOT v_lock_acquired THEN
        RAISE EXCEPTION 'Failed to acquire credential lock for org %', p_org_id;
    END IF;
    
    -- Get raw credentials from vault
    v_raw_credentials := private.get_tenant_credentials(p_org_id);
    
    -- Return credentials joined with n8n credential mappings
    RETURN QUERY
    SELECT 
        tcm.service_type,
        CASE 
            WHEN v_raw_credentials IS NOT NULL 
            THEN v_raw_credentials->tcm.service_type 
            ELSE NULL 
        END AS credentials,
        tcm.n8n_credential_id
    FROM tenant_credential_mappings tcm
    WHERE tcm.organization_id = p_org_id
    AND tcm.is_active = TRUE
    AND (p_service_types IS NULL OR tcm.service_type = ANY(p_service_types));
END;
$$;

COMMENT ON FUNCTION fn_get_credentials_with_lock(UUID, TEXT[]) IS 
    'Retrieves tenant credentials from vault with n8n credential mappings. Holds an advisory lock during the transaction.';


-- =============================================================================
-- GRANTS FOR NEW FUNCTIONS
-- =============================================================================

GRANT EXECUTE ON FUNCTION auth.clerk_email TO authenticated;
GRANT EXECUTE ON FUNCTION auth.clerk_session_id TO authenticated;
GRANT EXECUTE ON FUNCTION auth.clerk_has_org_role TO authenticated;
GRANT EXECUTE ON FUNCTION auth.clerk_is_org_admin TO authenticated;
GRANT ALL ON tenant_credential_mappings TO service_role;


-- =============================================================================
-- DOCUMENTATION
-- =============================================================================

COMMENT ON POLICY "profiles_insert_own" ON profiles IS 
    'Allows authenticated Clerk users to create their own profile on first login.';
