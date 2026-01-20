-- =============================================================================
-- N8N ORCHESTRATION GATEWAY - INITIAL DATABASE SCHEMA
-- =============================================================================
-- This migration creates the production-grade schema for the B2B orchestration
-- gateway with Row-Level Security (RLS) and Supabase Vault integration.
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vault";

-- =============================================================================
-- CUSTOM TYPES
-- =============================================================================

-- Plan types for organizations
CREATE TYPE plan_type AS ENUM ('free', 'starter', 'professional', 'enterprise');

-- Invoice status
CREATE TYPE invoice_status AS ENUM ('pending', 'paid', 'failed', 'refunded', 'cancelled');

-- Execution status
CREATE TYPE execution_status AS ENUM ('pending', 'running', 'completed', 'failed', 'timeout');

-- Security event types
CREATE TYPE security_event_type AS ENUM (
    'login_success',
    'login_failure', 
    'suspicious_fingerprint',
    'hmac_validation_failed',
    'rate_limit_exceeded',
    'unauthorized_access',
    'token_expired',
    'invalid_api_key'
);

-- =============================================================================
-- PROFILES TABLE
-- =============================================================================
-- Stores user profiles synced from Clerk via webhooks or JWT claims

CREATE TABLE profiles (
    id TEXT PRIMARY KEY,  -- Clerk User ID (user_xxxxx format)
    name TEXT,
    username TEXT UNIQUE,
    email TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone TEXT,
    phone_verified BOOLEAN DEFAULT FALSE,
    company_name TEXT,
    avatar_url TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for email lookups
CREATE INDEX idx_profiles_email ON profiles(email);
CREATE INDEX idx_profiles_username ON profiles(username);

-- =============================================================================
-- ORGANIZATIONS TABLE
-- =============================================================================
-- Multi-tenant organizations with API keys and credit-based billing

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    tenant_id TEXT UNIQUE NOT NULL,  -- Unique tenant identifier for routing
    api_key_hash TEXT NOT NULL,  -- Argon2 or bcrypt hash of API key
    api_key_prefix TEXT NOT NULL,  -- First 8 chars for identification (e.g., "gw_live_")
    client_secret_hash TEXT,  -- Hash of client secret for HMAC signing
    credits INTEGER DEFAULT 0 NOT NULL CHECK (credits >= 0),
    plan_type plan_type DEFAULT 'free' NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    settings JSONB DEFAULT '{
        "webhook_url": null,
        "allowed_ips": [],
        "rate_limit_override": null,
        "features": {}
    }'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indexes for fast lookups
CREATE INDEX idx_organizations_owner ON organizations(owner_id);
CREATE INDEX idx_organizations_tenant ON organizations(tenant_id);
CREATE INDEX idx_organizations_api_key_prefix ON organizations(api_key_prefix);
CREATE INDEX idx_organizations_active ON organizations(is_active) WHERE is_active = TRUE;

-- =============================================================================
-- ORGANIZATION MEMBERS TABLE
-- =============================================================================
-- Junction table for organization membership

CREATE TYPE member_role AS ENUM ('owner', 'admin', 'member', 'viewer');

CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role member_role DEFAULT 'member' NOT NULL,
    invited_by TEXT REFERENCES profiles(id),
    joined_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    UNIQUE(organization_id, profile_id)
);

CREATE INDEX idx_org_members_org ON organization_members(organization_id);
CREATE INDEX idx_org_members_profile ON organization_members(profile_id);

-- =============================================================================
-- WORKFLOWS TABLE
-- =============================================================================
-- Maps organization workflows to n8n workflow IDs

CREATE TABLE workflows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    n8n_workflow_id TEXT NOT NULL,
    n8n_webhook_path TEXT NOT NULL,  -- The webhook path in n8n
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    credits_per_execution INTEGER DEFAULT 1 NOT NULL CHECK (credits_per_execution >= 0),
    timeout_seconds INTEGER DEFAULT 300 NOT NULL CHECK (timeout_seconds > 0),
    settings JSONB DEFAULT '{
        "retry_on_failure": false,
        "max_retries": 3,
        "input_schema": null,
        "output_schema": null
    }'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    UNIQUE(organization_id, n8n_workflow_id)
);

CREATE INDEX idx_workflows_org ON workflows(organization_id);
CREATE INDEX idx_workflows_active ON workflows(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_workflows_n8n_id ON workflows(n8n_workflow_id);

-- =============================================================================
-- USAGE LOGS TABLE
-- =============================================================================
-- Tracks all workflow executions for billing and analytics

CREATE TABLE usage_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workflow_id UUID REFERENCES workflows(id) ON DELETE SET NULL,
    profile_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    credits_used INTEGER NOT NULL DEFAULT 0,
    status execution_status DEFAULT 'pending' NOT NULL,
    execution_time_ms INTEGER,  -- Duration in milliseconds
    request_metadata JSONB DEFAULT '{}'::jsonb,  -- Sanitized request info
    response_metadata JSONB DEFAULT '{}'::jsonb,  -- Response summary
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    fingerprint_hash TEXT,  -- For security tracking
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    completed_at TIMESTAMPTZ
);

-- Indexes for querying usage
CREATE INDEX idx_usage_logs_org ON usage_logs(organization_id);
CREATE INDEX idx_usage_logs_workflow ON usage_logs(workflow_id);
CREATE INDEX idx_usage_logs_status ON usage_logs(status);
CREATE INDEX idx_usage_logs_created ON usage_logs(created_at DESC);
CREATE INDEX idx_usage_logs_org_time ON usage_logs(organization_id, created_at DESC);

-- Partitioning hint: Consider partitioning by created_at for large-scale deployments

-- =============================================================================
-- INVOICES TABLE
-- =============================================================================
-- Billing records for credit purchases and subscriptions

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL CHECK (amount >= 0),
    currency TEXT DEFAULT 'USD' NOT NULL,
    credits_purchased INTEGER DEFAULT 0,
    status invoice_status DEFAULT 'pending' NOT NULL,
    stripe_invoice_id TEXT UNIQUE,
    stripe_payment_intent_id TEXT,
    billing_period_start TIMESTAMPTZ,
    billing_period_end TIMESTAMPTZ,
    billing_date TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    paid_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX idx_invoices_org ON invoices(organization_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_billing_date ON invoices(billing_date DESC);
CREATE INDEX idx_invoices_stripe ON invoices(stripe_invoice_id);

-- =============================================================================
-- SECURITY LOGS TABLE
-- =============================================================================
-- Tracks security-related events for monitoring and alerting

CREATE TABLE security_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    profile_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    event_type security_event_type NOT NULL,
    severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    ip_address INET,
    user_agent TEXT,
    fingerprint_hash TEXT,
    request_path TEXT,
    request_method TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX idx_security_logs_org ON security_logs(organization_id);
CREATE INDEX idx_security_logs_event ON security_logs(event_type);
CREATE INDEX idx_security_logs_severity ON security_logs(severity);
CREATE INDEX idx_security_logs_created ON security_logs(created_at DESC);
CREATE INDEX idx_security_logs_ip ON security_logs(ip_address);

-- =============================================================================
-- API KEYS TABLE (Secondary keys beyond org main key)
-- =============================================================================
-- Organizations can create multiple API keys with different permissions

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,  -- For identification
    permissions JSONB DEFAULT '{"workflows": ["*"]}'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_by TEXT REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_org ON api_keys(organization_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;

-- =============================================================================
-- SUPABASE VAULT - TENANT CREDENTIALS
-- =============================================================================
-- Store sensitive tenant credentials in Supabase Vault
-- These are encrypted at rest and only accessible via RPC

-- Create a secure schema for vault operations
CREATE SCHEMA IF NOT EXISTS private;

-- Function to store tenant credentials in vault
CREATE OR REPLACE FUNCTION private.store_tenant_credentials(
    p_org_id UUID,
    p_credentials JSONB
) RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, vault
AS $$
DECLARE
    v_secret_id UUID;
    v_secret_name TEXT;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    -- Check if secret already exists and delete it
    DELETE FROM vault.secrets WHERE name = v_secret_name;
    
    -- Insert new secret
    INSERT INTO vault.secrets (name, secret, description)
    VALUES (
        v_secret_name,
        p_credentials::TEXT,
        'Encrypted credentials for tenant ' || p_org_id::TEXT
    )
    RETURNING id INTO v_secret_id;
    
    RETURN v_secret_id;
END;
$$;

-- Function to retrieve tenant credentials from vault
CREATE OR REPLACE FUNCTION private.get_tenant_credentials(
    p_org_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, vault
AS $$
DECLARE
    v_secret_name TEXT;
    v_credentials TEXT;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    SELECT decrypted_secret INTO v_credentials
    FROM vault.decrypted_secrets
    WHERE name = v_secret_name;
    
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
SET search_path = public, vault
AS $$
DECLARE
    v_secret_name TEXT;
    v_deleted BOOLEAN;
BEGIN
    v_secret_name := 'tenant_creds_' || p_org_id::TEXT;
    
    DELETE FROM vault.secrets WHERE name = v_secret_name;
    
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END;
$$;

-- =============================================================================
-- CREDIT MANAGEMENT RPC
-- =============================================================================

-- Function to deduct credits atomically with validation
CREATE OR REPLACE FUNCTION fn_deduct_credits(
    p_org_id UUID,
    p_amount INTEGER,
    p_workflow_id UUID DEFAULT NULL,
    p_profile_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
) RETURNS TABLE (
    success BOOLEAN,
    remaining_credits INTEGER,
    usage_log_id UUID,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_current_credits INTEGER;
    v_usage_id UUID;
    v_org_active BOOLEAN;
BEGIN
    -- Lock the organization row for update
    SELECT credits, is_active 
    INTO v_current_credits, v_org_active
    FROM organizations 
    WHERE id = p_org_id 
    FOR UPDATE;
    
    -- Check if organization exists
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 
            0, 
            NULL::UUID, 
            'Organization not found'::TEXT;
        RETURN;
    END IF;
    
    -- Check if organization is active
    IF NOT v_org_active THEN
        RETURN QUERY SELECT 
            FALSE, 
            v_current_credits, 
            NULL::UUID, 
            'Organization is inactive'::TEXT;
        RETURN;
    END IF;
    
    -- Check if enough credits
    IF v_current_credits < p_amount THEN
        RETURN QUERY SELECT 
            FALSE, 
            v_current_credits, 
            NULL::UUID, 
            'Insufficient credits'::TEXT;
        RETURN;
    END IF;
    
    -- Deduct credits
    UPDATE organizations 
    SET 
        credits = credits - p_amount,
        updated_at = NOW()
    WHERE id = p_org_id;
    
    -- Create usage log entry
    INSERT INTO usage_logs (
        organization_id,
        workflow_id,
        profile_id,
        credits_used,
        status,
        request_metadata
    ) VALUES (
        p_org_id,
        p_workflow_id,
        p_profile_id,
        p_amount,
        'pending',
        p_metadata
    )
    RETURNING id INTO v_usage_id;
    
    RETURN QUERY SELECT 
        TRUE, 
        v_current_credits - p_amount, 
        v_usage_id, 
        NULL::TEXT;
END;
$$;

-- Function to add credits (for purchases)
CREATE OR REPLACE FUNCTION fn_add_credits(
    p_org_id UUID,
    p_amount INTEGER,
    p_invoice_id UUID DEFAULT NULL
) RETURNS TABLE (
    success BOOLEAN,
    new_balance INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_new_balance INTEGER;
BEGIN
    -- Update credits
    UPDATE organizations 
    SET 
        credits = credits + p_amount,
        updated_at = NOW()
    WHERE id = p_org_id
    RETURNING credits INTO v_new_balance;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 
            0, 
            'Organization not found'::TEXT;
        RETURN;
    END IF;
    
    -- Update invoice if provided
    IF p_invoice_id IS NOT NULL THEN
        UPDATE invoices 
        SET 
            credits_purchased = p_amount,
            status = 'paid',
            paid_at = NOW(),
            updated_at = NOW()
        WHERE id = p_invoice_id;
    END IF;
    
    RETURN QUERY SELECT 
        TRUE, 
        v_new_balance, 
        NULL::TEXT;
END;
$$;

-- Function to update usage log status
CREATE OR REPLACE FUNCTION fn_update_usage_status(
    p_usage_id UUID,
    p_status execution_status,
    p_execution_time_ms INTEGER DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL,
    p_response_metadata JSONB DEFAULT NULL
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE usage_logs 
    SET 
        status = p_status,
        execution_time_ms = COALESCE(p_execution_time_ms, execution_time_ms),
        error_message = p_error_message,
        response_metadata = COALESCE(p_response_metadata, response_metadata),
        completed_at = CASE WHEN p_status IN ('completed', 'failed', 'timeout') THEN NOW() ELSE completed_at END
    WHERE id = p_usage_id;
    
    RETURN FOUND;
END;
$$;

-- Function to refund credits on failure
CREATE OR REPLACE FUNCTION fn_refund_credits(
    p_usage_id UUID
) RETURNS TABLE (
    success BOOLEAN,
    refunded_amount INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_org_id UUID;
    v_credits INTEGER;
    v_status execution_status;
BEGIN
    -- Get usage log details
    SELECT organization_id, credits_used, status
    INTO v_org_id, v_credits, v_status
    FROM usage_logs
    WHERE id = p_usage_id
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 0, 'Usage log not found'::TEXT;
        RETURN;
    END IF;
    
    -- Only refund if status is failed or timeout
    IF v_status NOT IN ('failed', 'timeout') THEN
        RETURN QUERY SELECT FALSE, 0, 'Can only refund failed or timeout executions'::TEXT;
        RETURN;
    END IF;
    
    -- Refund credits
    UPDATE organizations
    SET credits = credits + v_credits,
        updated_at = NOW()
    WHERE id = v_org_id;
    
    -- Mark usage log as refunded
    UPDATE usage_logs
    SET request_metadata = request_metadata || '{"refunded": true}'::jsonb
    WHERE id = p_usage_id;
    
    RETURN QUERY SELECT TRUE, v_credits, NULL::TEXT;
END;
$$;

-- =============================================================================
-- ROW-LEVEL SECURITY POLICIES
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- PROFILES POLICIES
-- =============================================================================

-- Users can read their own profile
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT
    USING (auth.uid()::TEXT = id);

-- Users can update their own profile
CREATE POLICY "profiles_update_own" ON profiles
    FOR UPDATE
    USING (auth.uid()::TEXT = id)
    WITH CHECK (auth.uid()::TEXT = id);

-- Service role can manage all profiles
CREATE POLICY "profiles_service_role" ON profiles
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- ORGANIZATIONS POLICIES
-- =============================================================================

-- Members can read their organizations
CREATE POLICY "organizations_select_member" ON organizations
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.uid()::TEXT
        )
    );

-- Owners and admins can update their organizations
CREATE POLICY "organizations_update_admin" ON organizations
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.uid()::TEXT
            AND role IN ('owner', 'admin')
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND profile_id = auth.uid()::TEXT
            AND role IN ('owner', 'admin')
        )
    );

-- Service role can manage all organizations
CREATE POLICY "organizations_service_role" ON organizations
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- ORGANIZATION MEMBERS POLICIES
-- =============================================================================

-- Members can see other members in their org
CREATE POLICY "org_members_select" ON organization_members
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.organization_id = organization_members.organization_id
            AND om.profile_id = auth.uid()::TEXT
        )
    );

-- Owners and admins can manage members
CREATE POLICY "org_members_admin" ON organization_members
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members om
            WHERE om.organization_id = organization_members.organization_id
            AND om.profile_id = auth.uid()::TEXT
            AND om.role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "org_members_service_role" ON organization_members
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- WORKFLOWS POLICIES
-- =============================================================================

-- Members can read workflows
CREATE POLICY "workflows_select_member" ON workflows
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = auth.uid()::TEXT
        )
    );

-- Admins can manage workflows
CREATE POLICY "workflows_admin" ON workflows
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = workflows.organization_id
            AND profile_id = auth.uid()::TEXT
            AND role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "workflows_service_role" ON workflows
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- USAGE LOGS POLICIES
-- =============================================================================

-- Members can read their org's usage logs
CREATE POLICY "usage_logs_select_member" ON usage_logs
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = usage_logs.organization_id
            AND profile_id = auth.uid()::TEXT
        )
    );

-- Only service role can insert/update usage logs
CREATE POLICY "usage_logs_service_role" ON usage_logs
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- INVOICES POLICIES
-- =============================================================================

-- Members can read their org's invoices
CREATE POLICY "invoices_select_member" ON invoices
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = invoices.organization_id
            AND profile_id = auth.uid()::TEXT
        )
    );

-- Service role manages invoices
CREATE POLICY "invoices_service_role" ON invoices
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- SECURITY LOGS POLICIES
-- =============================================================================

-- Admins can read security logs
CREATE POLICY "security_logs_select_admin" ON security_logs
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = security_logs.organization_id
            AND profile_id = auth.uid()::TEXT
            AND role IN ('owner', 'admin')
        )
    );

-- Service role manages security logs
CREATE POLICY "security_logs_service_role" ON security_logs
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- API KEYS POLICIES
-- =============================================================================

-- Admins can manage API keys
CREATE POLICY "api_keys_admin" ON api_keys
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = api_keys.organization_id
            AND profile_id = auth.uid()::TEXT
            AND role IN ('owner', 'admin')
        )
    );

-- Service role bypass
CREATE POLICY "api_keys_service_role" ON api_keys
    FOR ALL
    USING (auth.role() = 'service_role');

-- =============================================================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workflows_updated_at
    BEFORE UPDATE ON workflows
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_invoices_updated_at
    BEFORE UPDATE ON invoices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- TRIGGER FOR AUTO-CREATING ORGANIZATION OWNER MEMBERSHIP
-- =============================================================================

CREATE OR REPLACE FUNCTION create_owner_membership()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO organization_members (organization_id, profile_id, role)
    VALUES (NEW.id, NEW.owner_id, 'owner');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER create_org_owner_membership
    AFTER INSERT ON organizations
    FOR EACH ROW EXECUTE FUNCTION create_owner_membership();

-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant execute on functions to authenticated users
GRANT EXECUTE ON FUNCTION fn_deduct_credits TO authenticated;
GRANT EXECUTE ON FUNCTION fn_add_credits TO authenticated;
GRANT EXECUTE ON FUNCTION fn_update_usage_status TO authenticated;
GRANT EXECUTE ON FUNCTION fn_refund_credits TO authenticated;

-- Service role gets full access to private schema functions
GRANT USAGE ON SCHEMA private TO service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA private TO service_role;

-- =============================================================================
-- COMMENTS FOR DOCUMENTATION
-- =============================================================================

COMMENT ON TABLE profiles IS 'User profiles synced from Clerk authentication provider';
COMMENT ON TABLE organizations IS 'Multi-tenant organizations with API credentials and billing';
COMMENT ON TABLE workflows IS 'n8n workflow mappings for each organization';
COMMENT ON TABLE usage_logs IS 'Execution logs for billing, analytics, and audit trail';
COMMENT ON TABLE invoices IS 'Billing records for credit purchases';
COMMENT ON TABLE security_logs IS 'Security event logging for monitoring and alerting';
COMMENT ON TABLE api_keys IS 'Additional API keys for organizations';

COMMENT ON FUNCTION fn_deduct_credits IS 'Atomically deduct credits with validation, returns success status and usage log ID';
COMMENT ON FUNCTION fn_add_credits IS 'Add credits to organization, typically after payment';
COMMENT ON FUNCTION fn_refund_credits IS 'Refund credits for failed executions';
COMMENT ON FUNCTION private.store_tenant_credentials IS 'Store encrypted tenant credentials in Supabase Vault';
COMMENT ON FUNCTION private.get_tenant_credentials IS 'Retrieve decrypted tenant credentials from Supabase Vault';
