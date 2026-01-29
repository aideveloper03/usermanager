-- =============================================================================
-- N8N ORCHESTRATION GATEWAY - CLERK + SUPABASE V2 NATIVE INTEGRATION
-- =============================================================================
-- This migration implements the latest Clerk + Supabase integration patterns.
-- 
-- Key improvements:
-- 1. Uses auth.jwt() for JWT claim access (newer Supabase pattern)
-- 2. Adds proper session context handling
-- 3. Implements optimized RLS helper functions
-- 4. Adds support for Clerk organization switching
-- 5. Improves credential injection with better locking
-- =============================================================================

-- =============================================================================
-- IMPROVED JWT CLAIM HELPER FUNCTIONS
-- =============================================================================
-- These functions provide a unified interface for accessing Clerk JWT claims
-- in RLS policies and application queries.

-- Drop existing functions to recreate with improved logic
DROP FUNCTION IF EXISTS auth.clerk_user_id() CASCADE;
DROP FUNCTION IF EXISTS auth.clerk_org_id() CASCADE;
DROP FUNCTION IF EXISTS auth.clerk_org_role() CASCADE;
DROP FUNCTION IF EXISTS auth.is_authenticated() CASCADE;

-- Function to get Clerk user ID from JWT claims
-- Supports both native Supabase auth and direct JWT verification
CREATE OR REPLACE FUNCTION auth.clerk_user_id()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT COALESCE(
        -- Method 1: Native Supabase auth.jwt() function (recommended)
        (auth.jwt() ->> 'sub'),
        -- Method 2: Request JWT claims from header (legacy/custom setup)
        (nullif(current_setting('request.jwt.claims', true), '')::json ->> 'sub'),
        -- Method 3: Fallback to auth.uid() for native Supabase auth
        (auth.uid())::TEXT
    );
$$;

COMMENT ON FUNCTION auth.clerk_user_id() IS 
    'Returns the Clerk user ID from JWT. Supports multiple integration patterns.';


-- Function to get Clerk organization ID
CREATE OR REPLACE FUNCTION auth.clerk_org_id()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT COALESCE(
        (auth.jwt() ->> 'org_id'),
        (nullif(current_setting('request.jwt.claims', true), '')::json ->> 'org_id')
    );
$$;

COMMENT ON FUNCTION auth.clerk_org_id() IS 
    'Returns the active Clerk organization ID from JWT.';


-- Function to get user's role within the organization
CREATE OR REPLACE FUNCTION auth.clerk_org_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT COALESCE(
        (auth.jwt() ->> 'org_role'),
        (nullif(current_setting('request.jwt.claims', true), '')::json ->> 'org_role')
    );
$$;

COMMENT ON FUNCTION auth.clerk_org_role() IS 
    'Returns the user role in the active organization.';


-- Function to check if user is authenticated
CREATE OR REPLACE FUNCTION auth.is_authenticated()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT auth.clerk_user_id() IS NOT NULL;
$$;

COMMENT ON FUNCTION auth.is_authenticated() IS 
    'Returns true if the request has valid authentication.';


-- Function to get all JWT claims as JSONB
CREATE OR REPLACE FUNCTION auth.jwt_claims()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT COALESCE(
        auth.jwt()::JSONB,
        (nullif(current_setting('request.jwt.claims', true), '')::JSONB)
    );
$$;

COMMENT ON FUNCTION auth.jwt_claims() IS 
    'Returns all JWT claims as JSONB for advanced use cases.';


-- Function to check if user has specific permission
CREATE OR REPLACE FUNCTION auth.has_org_permission(required_roles TEXT[])
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT auth.clerk_org_role() = ANY(required_roles);
$$;

COMMENT ON FUNCTION auth.has_org_permission(TEXT[]) IS 
    'Checks if the authenticated user has one of the required organization roles.';


-- =============================================================================
-- ORGANIZATION MEMBERSHIP HELPER
-- =============================================================================
-- Efficient function to check organization membership

CREATE OR REPLACE FUNCTION auth.is_org_member(check_org_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM organization_members 
        WHERE organization_id = check_org_id 
        AND profile_id = auth.clerk_user_id()
    );
$$;

COMMENT ON FUNCTION auth.is_org_member(UUID) IS 
    'Checks if the authenticated user is a member of the specified organization.';


CREATE OR REPLACE FUNCTION auth.is_org_admin(check_org_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM organization_members 
        WHERE organization_id = check_org_id 
        AND profile_id = auth.clerk_user_id()
        AND role IN ('owner', 'admin')
    );
$$;

COMMENT ON FUNCTION auth.is_org_admin(UUID) IS 
    'Checks if the authenticated user is an admin of the specified organization.';


-- =============================================================================
-- IMPROVED CREDENTIAL LOCKING WITH SERIAL EXECUTION
-- =============================================================================
-- These functions implement an improved pattern for credential injection
-- that ensures serialized execution per tenant.

-- Table to track active credential operations (improved version)
DROP TABLE IF EXISTS credential_operations CASCADE;
CREATE TABLE IF NOT EXISTS credential_operations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    operation_type TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    worker_id TEXT,  -- For debugging which worker has the lock
    CONSTRAINT active_operation_per_org UNIQUE (organization_id, completed_at)
);

CREATE INDEX idx_cred_ops_org ON credential_operations(organization_id);
CREATE INDEX idx_cred_ops_expires ON credential_operations(expires_at) WHERE completed_at IS NULL;

-- Function to acquire credential operation lock
CREATE OR REPLACE FUNCTION fn_acquire_credential_operation(
    p_org_id UUID,
    p_operation_type TEXT DEFAULT 'injection',
    p_timeout_seconds INTEGER DEFAULT 30,
    p_worker_id TEXT DEFAULT NULL
) RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_operation_id UUID;
    v_lock_key BIGINT;
BEGIN
    -- Generate lock key from org_id
    v_lock_key := ('x' || substr(md5(p_org_id::TEXT), 1, 16))::bit(64)::bigint;
    
    -- Try to acquire advisory lock (non-blocking)
    IF NOT pg_try_advisory_xact_lock(v_lock_key) THEN
        -- If can't acquire, clean up stale operations and try again
        DELETE FROM credential_operations 
        WHERE organization_id = p_org_id 
        AND expires_at < NOW() 
        AND completed_at IS NULL;
        
        -- Try one more time
        IF NOT pg_try_advisory_xact_lock(v_lock_key) THEN
            RAISE EXCEPTION 'Could not acquire credential lock for org %', p_org_id
                USING HINT = 'Another operation is in progress';
        END IF;
    END IF;
    
    -- Create operation record
    INSERT INTO credential_operations (
        organization_id, 
        operation_type, 
        expires_at, 
        worker_id
    ) VALUES (
        p_org_id, 
        p_operation_type, 
        NOW() + (p_timeout_seconds || ' seconds')::INTERVAL,
        p_worker_id
    )
    RETURNING id INTO v_operation_id;
    
    RETURN v_operation_id;
END;
$$;

COMMENT ON FUNCTION fn_acquire_credential_operation IS 
    'Acquires a lock for credential operations. Returns operation ID on success.';


-- Function to release credential operation lock
CREATE OR REPLACE FUNCTION fn_release_credential_operation(
    p_operation_id UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE credential_operations 
    SET completed_at = NOW() 
    WHERE id = p_operation_id AND completed_at IS NULL;
    
    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION fn_release_credential_operation IS 
    'Releases a credential operation lock by marking it completed.';


-- Cleanup function for stale operations (run periodically)
CREATE OR REPLACE FUNCTION fn_cleanup_stale_credential_operations()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    -- Delete operations that expired more than 5 minutes ago
    DELETE FROM credential_operations 
    WHERE expires_at < NOW() - INTERVAL '5 minutes';
    
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    
    -- Also delete completed operations older than 1 hour
    DELETE FROM credential_operations 
    WHERE completed_at IS NOT NULL 
    AND completed_at < NOW() - INTERVAL '1 hour';
    
    RETURN v_deleted;
END;
$$;


-- =============================================================================
-- IMPROVED PROFILE SYNC WITH METADATA MERGE
-- =============================================================================

CREATE OR REPLACE FUNCTION fn_sync_clerk_user(
    p_user_id TEXT,
    p_email TEXT,
    p_name TEXT DEFAULT NULL,
    p_username TEXT DEFAULT NULL,
    p_avatar_url TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::JSONB,
    p_external_accounts JSONB DEFAULT '[]'::JSONB
) RETURNS TABLE (
    profile_id TEXT,
    is_new_user BOOLEAN,
    merged_metadata JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_profile_id TEXT;
    v_is_new BOOLEAN := FALSE;
    v_existing_metadata JSONB;
    v_merged JSONB;
BEGIN
    -- Check if profile exists
    SELECT id, metadata INTO v_profile_id, v_existing_metadata
    FROM profiles
    WHERE id = p_user_id;
    
    IF v_profile_id IS NULL THEN
        -- New user
        v_is_new := TRUE;
        v_merged := COALESCE(p_metadata, '{}'::JSONB) || jsonb_build_object(
            'external_accounts', p_external_accounts,
            'synced_at', NOW()
        );
        
        INSERT INTO profiles (
            id, email, name, username, avatar_url, 
            metadata, email_verified
        ) VALUES (
            p_user_id, p_email, p_name, p_username, p_avatar_url,
            v_merged, TRUE
        )
        RETURNING id INTO v_profile_id;
    ELSE
        -- Existing user - merge metadata
        v_merged := COALESCE(v_existing_metadata, '{}'::JSONB) 
            || COALESCE(p_metadata, '{}'::JSONB)
            || jsonb_build_object(
                'external_accounts', p_external_accounts,
                'synced_at', NOW()
            );
        
        UPDATE profiles SET
            email = COALESCE(p_email, email),
            name = COALESCE(p_name, name),
            username = COALESCE(p_username, username),
            avatar_url = COALESCE(p_avatar_url, avatar_url),
            metadata = v_merged,
            updated_at = NOW()
        WHERE id = p_user_id;
    END IF;
    
    RETURN QUERY SELECT v_profile_id, v_is_new, v_merged;
END;
$$;

COMMENT ON FUNCTION fn_sync_clerk_user IS 
    'Syncs user data from Clerk webhooks with metadata merging.';


-- =============================================================================
-- CLERK ORGANIZATION SYNC FUNCTION
-- =============================================================================
-- Syncs organization data from Clerk organization webhooks

CREATE OR REPLACE FUNCTION fn_sync_clerk_organization(
    p_clerk_org_id TEXT,
    p_name TEXT,
    p_slug TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::JSONB
) RETURNS TABLE (
    organization_id UUID,
    is_new_org BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_org_id UUID;
    v_is_new BOOLEAN := FALSE;
BEGIN
    -- Look up organization by clerk org ID stored in metadata
    SELECT id INTO v_org_id
    FROM organizations
    WHERE settings->>'clerk_org_id' = p_clerk_org_id
    OR tenant_id = p_clerk_org_id;  -- Fallback to tenant_id
    
    IF v_org_id IS NULL THEN
        -- Note: We don't auto-create organizations from Clerk
        -- They should be created through the API with proper billing setup
        RETURN QUERY SELECT NULL::UUID, FALSE;
        RETURN;
    END IF;
    
    -- Update organization metadata
    UPDATE organizations SET
        name = COALESCE(p_name, name),
        settings = settings || jsonb_build_object(
            'clerk_org_id', p_clerk_org_id,
            'clerk_slug', p_slug,
            'clerk_metadata', p_metadata,
            'clerk_synced_at', NOW()
        ),
        updated_at = NOW()
    WHERE id = v_org_id;
    
    RETURN QUERY SELECT v_org_id, v_is_new;
END;
$$;

COMMENT ON FUNCTION fn_sync_clerk_organization IS 
    'Syncs organization data from Clerk organization webhooks.';


-- =============================================================================
-- SYNC CLERK MEMBERSHIP FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION fn_sync_clerk_membership(
    p_clerk_org_id TEXT,
    p_user_id TEXT,
    p_role TEXT,
    p_action TEXT  -- 'add', 'update', 'remove'
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_org_id UUID;
    v_member_role member_role;
BEGIN
    -- Look up organization
    SELECT id INTO v_org_id
    FROM organizations
    WHERE settings->>'clerk_org_id' = p_clerk_org_id
    OR tenant_id = p_clerk_org_id;
    
    IF v_org_id IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Map Clerk role to our role enum
    v_member_role := CASE p_role
        WHEN 'org:admin' THEN 'admin'::member_role
        WHEN 'admin' THEN 'admin'::member_role
        WHEN 'org:member' THEN 'member'::member_role
        WHEN 'member' THEN 'member'::member_role
        ELSE 'member'::member_role
    END;
    
    IF p_action = 'remove' THEN
        DELETE FROM organization_members
        WHERE organization_id = v_org_id AND profile_id = p_user_id;
    ELSIF p_action IN ('add', 'update') THEN
        INSERT INTO organization_members (organization_id, profile_id, role)
        VALUES (v_org_id, p_user_id, v_member_role)
        ON CONFLICT (organization_id, profile_id) 
        DO UPDATE SET role = v_member_role;
    END IF;
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION fn_sync_clerk_membership IS 
    'Syncs organization membership changes from Clerk webhooks.';


-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant execute on helper functions to authenticated users
GRANT EXECUTE ON FUNCTION auth.clerk_user_id TO authenticated, anon;
GRANT EXECUTE ON FUNCTION auth.clerk_org_id TO authenticated, anon;
GRANT EXECUTE ON FUNCTION auth.clerk_org_role TO authenticated, anon;
GRANT EXECUTE ON FUNCTION auth.is_authenticated TO authenticated, anon;
GRANT EXECUTE ON FUNCTION auth.jwt_claims TO authenticated;
GRANT EXECUTE ON FUNCTION auth.has_org_permission TO authenticated;
GRANT EXECUTE ON FUNCTION auth.is_org_member TO authenticated;
GRANT EXECUTE ON FUNCTION auth.is_org_admin TO authenticated;

-- Service role functions
GRANT EXECUTE ON FUNCTION fn_acquire_credential_operation TO service_role;
GRANT EXECUTE ON FUNCTION fn_release_credential_operation TO service_role;
GRANT EXECUTE ON FUNCTION fn_cleanup_stale_credential_operations TO service_role;
GRANT EXECUTE ON FUNCTION fn_sync_clerk_user TO service_role;
GRANT EXECUTE ON FUNCTION fn_sync_clerk_organization TO service_role;
GRANT EXECUTE ON FUNCTION fn_sync_clerk_membership TO service_role;

-- Table access for service role
GRANT ALL ON credential_operations TO service_role;


-- =============================================================================
-- SCHEDULED CLEANUP (For Supabase pg_cron if available)
-- =============================================================================
-- Uncomment if pg_cron is available in your Supabase instance
-- SELECT cron.schedule(
--     'cleanup-credential-operations',
--     '*/5 * * * *',  -- Every 5 minutes
--     $$SELECT fn_cleanup_stale_credential_operations()$$
-- );
