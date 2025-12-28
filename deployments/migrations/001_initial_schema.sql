-- ZT-NMS Database Schema
-- Version: 1.0.0
-- PostgreSQL 15+

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- IDENTITIES
-- ============================================

CREATE TYPE identity_type AS ENUM ('operator', 'device', 'service');
CREATE TYPE identity_status AS ENUM ('active', 'suspended', 'revoked');

CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type identity_type NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    public_key BYTEA NOT NULL,
    certificate BYTEA,
    status identity_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES identities(id)
);

CREATE INDEX idx_identities_type ON identities(type);
CREATE INDEX idx_identities_status ON identities(status);
CREATE INDEX idx_identities_public_key ON identities(public_key);
CREATE INDEX idx_identities_attributes ON identities USING GIN (attributes);
CREATE INDEX idx_identities_created_by ON identities(created_by);

-- Operator-specific index
CREATE INDEX idx_identities_username ON identities((attributes->>'username')) 
    WHERE type = 'operator';

-- Device-specific index
CREATE INDEX idx_identities_hostname ON identities((attributes->>'hostname')) 
    WHERE type = 'device';

-- ============================================
-- CAPABILITIES
-- ============================================

CREATE TABLE capability_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id UUID NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1,
    issuer VARCHAR(255) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    subject_id UUID NOT NULL REFERENCES identities(id),
    subject_hash BYTEA NOT NULL,
    grants JSONB NOT NULL,
    validity JSONB NOT NULL,
    context_requirements JSONB,
    delegation JSONB,
    parent_token_id UUID REFERENCES capability_tokens(token_id),
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    approvals JSONB,
    issuer_signature BYTEA NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES identities(id),
    revocation_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_capability_tokens_subject ON capability_tokens(subject_id);
CREATE INDEX idx_capability_tokens_parent ON capability_tokens(parent_token_id);
CREATE INDEX idx_capability_tokens_issuer ON capability_tokens(issuer);
CREATE INDEX idx_capability_tokens_revoked ON capability_tokens(revoked);
CREATE INDEX idx_capability_tokens_validity ON capability_tokens USING GIN (validity);

-- ============================================
-- POLICIES
-- ============================================

CREATE TYPE policy_type AS ENUM ('access', 'config', 'deployment', 'network');
CREATE TYPE policy_status AS ENUM ('draft', 'active', 'archived');

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    type policy_type NOT NULL,
    definition JSONB NOT NULL,
    compiled BYTEA,
    status policy_status NOT NULL DEFAULT 'draft',
    effective_from TIMESTAMP WITH TIME ZONE,
    effective_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES identities(id),
    approved_by UUID REFERENCES identities(id),
    approval_signature BYTEA
);

CREATE UNIQUE INDEX idx_policies_name_version ON policies(name, version);
CREATE INDEX idx_policies_type ON policies(type);
CREATE INDEX idx_policies_status ON policies(status);
CREATE INDEX idx_policies_effective ON policies(effective_from, effective_until);

-- Policy versions history
CREATE TABLE policy_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES policies(id),
    version INTEGER NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES identities(id),
    change_log TEXT
);

CREATE INDEX idx_policy_versions_policy ON policy_versions(policy_id);

-- ============================================
-- DEVICES
-- ============================================

CREATE TYPE device_status AS ENUM ('unknown', 'online', 'offline', 'degraded', 'maintenance');
CREATE TYPE trust_status AS ENUM ('unknown', 'verified', 'untrusted', 'quarantined');
CREATE TYPE protocol_type AS ENUM ('ssh', 'netconf', 'restconf', 'snmp', 'https', 'gnmi');

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id),
    hostname VARCHAR(255) NOT NULL,
    vendor VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    asset_tag VARCHAR(100),
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    firmware_version VARCHAR(50),
    role VARCHAR(50) NOT NULL,
    criticality VARCHAR(20) NOT NULL DEFAULT 'medium',
    tags TEXT[],
    location_id UUID,
    rack_position VARCHAR(50),
    management_ip INET NOT NULL,
    management_port INTEGER,
    management_protocol protocol_type NOT NULL DEFAULT 'ssh',
    supports_agent BOOLEAN NOT NULL DEFAULT FALSE,
    agent_version VARCHAR(50),
    status device_status NOT NULL DEFAULT 'unknown',
    trust_status trust_status NOT NULL DEFAULT 'unknown',
    last_seen TIMESTAMP WITH TIME ZONE,
    last_attestation TIMESTAMP WITH TIME ZONE,
    current_config_sequence BIGINT NOT NULL DEFAULT 0,
    current_config_hash BYTEA,
    startup_config_hash BYTEA,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_identity ON devices(identity_id);
CREATE INDEX idx_devices_hostname ON devices(hostname);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_trust_status ON devices(trust_status);
CREATE INDEX idx_devices_role ON devices(role);
CREATE INDEX idx_devices_criticality ON devices(criticality);
CREATE INDEX idx_devices_management_ip ON devices(management_ip);
CREATE INDEX idx_devices_tags ON devices USING GIN (tags);

-- Device credentials (encrypted)
CREATE TABLE device_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol protocol_type NOT NULL,
    encrypted_data BYTEA NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    last_rotated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(device_id, protocol)
);

-- ============================================
-- CONFIGURATIONS
-- ============================================

CREATE TYPE deployment_status AS ENUM ('pending', 'approved', 'deploying', 'applied', 'failed', 'rolled_back');

CREATE TABLE config_blocks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    sequence BIGINT NOT NULL,
    prev_hash BYTEA,
    merkle_root BYTEA,
    block_hash BYTEA NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    intent JSONB,
    configuration JSONB NOT NULL,
    diff JSONB,
    validation JSONB,
    author_id UUID NOT NULL REFERENCES identities(id),
    author_signature BYTEA NOT NULL,
    approvals JSONB,
    system_signature BYTEA,
    deployment_status deployment_status NOT NULL DEFAULT 'pending',
    device_signature BYTEA,
    applied_at TIMESTAMP WITH TIME ZONE,
    device_config_hash BYTEA,
    UNIQUE(device_id, sequence)
);

CREATE INDEX idx_config_blocks_device ON config_blocks(device_id);
CREATE INDEX idx_config_blocks_sequence ON config_blocks(device_id, sequence DESC);
CREATE INDEX idx_config_blocks_status ON config_blocks(deployment_status);
CREATE INDEX idx_config_blocks_author ON config_blocks(author_id);
CREATE INDEX idx_config_blocks_timestamp ON config_blocks(timestamp);

-- ============================================
-- ATTESTATION
-- ============================================

CREATE TYPE attestation_type AS ENUM ('tpm', 'software', 'remote');
CREATE TYPE attestation_status AS ENUM ('pending', 'verified', 'failed', 'expired', 'unknown');

CREATE TABLE attestation_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    type attestation_type NOT NULL,
    measurements JSONB NOT NULL,
    pcr_values JSONB,
    tpm_signature BYTEA,
    aik_cert BYTEA,
    software_signature BYTEA,
    nonce BYTEA NOT NULL,
    quote_data BYTEA,
    status attestation_status NOT NULL DEFAULT 'pending',
    verification_result JSONB,
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_attestation_device ON attestation_reports(device_id);
CREATE INDEX idx_attestation_timestamp ON attestation_reports(timestamp);
CREATE INDEX idx_attestation_status ON attestation_reports(status);

-- Expected measurements for devices
CREATE TABLE expected_measurements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) UNIQUE,
    firmware_hash BYTEA,
    os_hash BYTEA,
    agent_hash BYTEA,
    expected_pcrs JSONB,
    allowed_processes TEXT[],
    allowed_process_hashes BYTEA[],
    allowed_modules TEXT[],
    expected_ports JSONB,
    min_os_version VARCHAR(50),
    min_agent_version VARCHAR(50),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_by UUID NOT NULL REFERENCES identities(id)
);

-- ============================================
-- AUDIT
-- ============================================

CREATE TYPE audit_event_type AS ENUM (
    'identity.create', 'identity.update', 'identity.delete', 'identity.auth', 'identity.auth_failed',
    'capability.request', 'capability.issue', 'capability.use', 'capability.revoke', 'capability.expire',
    'operation.request', 'operation.approve', 'operation.execute', 'operation.success', 'operation.failed', 'operation.denied',
    'config.create', 'config.validate', 'config.approve', 'config.deploy', 'config.apply', 'config.rollback',
    'policy.create', 'policy.update', 'policy.activate', 'policy.evaluate',
    'device.register', 'device.attest', 'device.attest_failed', 'device.connect', 'device.disconnect',
    'security.alert', 'security.incident', 'security.violation',
    'system.startup', 'system.shutdown', 'system.config', 'system.backup'
);

CREATE TYPE audit_severity AS ENUM ('debug', 'info', 'warning', 'error', 'critical');
CREATE TYPE audit_result AS ENUM ('success', 'failure', 'denied', 'pending');

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence BIGSERIAL NOT NULL,
    prev_hash BYTEA,
    event_hash BYTEA NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type audit_event_type NOT NULL,
    severity audit_severity NOT NULL DEFAULT 'info',
    actor_id UUID REFERENCES identities(id),
    actor_type identity_type,
    actor_name VARCHAR(255),
    resource_type VARCHAR(100),
    resource_id UUID,
    resource_name VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    result audit_result NOT NULL,
    details JSONB,
    capability_id UUID,
    operation_id UUID,
    session_id UUID,
    operation_signature BYTEA,
    source_ip INET,
    user_agent TEXT,
    request_id VARCHAR(100)
);

-- Partitioned by month for performance
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_events_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_severity ON audit_events(severity);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_events_resource ON audit_events(resource_type, resource_id);
CREATE INDEX idx_audit_events_sequence ON audit_events(sequence);

-- ============================================
-- SESSIONS
-- ============================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id),
    device_id UUID REFERENCES devices(id),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    source_ip INET,
    user_agent TEXT,
    recording_path TEXT,
    command_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_sessions_identity ON sessions(identity_id);
CREATE INDEX idx_sessions_device ON sessions(device_id);
CREATE INDEX idx_sessions_started ON sessions(started_at);

-- Session commands
CREATE TABLE session_commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    command TEXT NOT NULL,
    output TEXT,
    duration_ms INTEGER,
    success BOOLEAN
);

CREATE INDEX idx_session_commands_session ON session_commands(session_id);
CREATE INDEX idx_session_commands_timestamp ON session_commands(timestamp);

-- ============================================
-- LOCATIONS
-- ============================================

CREATE TABLE locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    parent_id UUID REFERENCES locations(id),
    address JSONB,
    coordinates POINT,
    metadata JSONB
);

CREATE INDEX idx_locations_parent ON locations(parent_id);
CREATE INDEX idx_locations_type ON locations(type);

-- ============================================
-- VRFs
-- ============================================

CREATE TABLE vrfs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    rd VARCHAR(50),
    import_rt TEXT[],
    export_rt TEXT[],
    description TEXT,
    UNIQUE(name)
);

-- ============================================
-- DEVICE GROUPS
-- ============================================

CREATE TABLE device_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'static',
    query JSONB,
    metadata JSONB
);

CREATE TABLE device_group_members (
    group_id UUID NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);

-- ============================================
-- FUNCTIONS
-- ============================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables
CREATE TRIGGER update_identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Audit chain verification function
CREATE OR REPLACE FUNCTION verify_audit_chain(start_seq BIGINT, end_seq BIGINT)
RETURNS TABLE(valid BOOLEAN, broken_at BIGINT) AS $$
DECLARE
    prev_hash BYTEA := NULL;
    curr_hash BYTEA;
    curr_seq BIGINT;
    rec RECORD;
BEGIN
    FOR rec IN 
        SELECT sequence, event_hash, a.prev_hash as stored_prev_hash
        FROM audit_events a
        WHERE sequence BETWEEN start_seq AND end_seq
        ORDER BY sequence
    LOOP
        IF prev_hash IS NOT NULL AND rec.stored_prev_hash != prev_hash THEN
            RETURN QUERY SELECT FALSE, rec.sequence;
            RETURN;
        END IF;
        prev_hash := rec.event_hash;
    END LOOP;
    
    RETURN QUERY SELECT TRUE, NULL::BIGINT;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- INITIAL DATA
-- ============================================

-- System identity for automated actions
INSERT INTO identities (id, type, attributes, public_key, status)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'service',
    '{"name": "system", "owner": "zt-nms", "purpose": "System operations"}',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'active'
);

-- Default policies
INSERT INTO policies (id, name, type, description, definition, status, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default-deny',
    'access',
    'Default deny all policy',
    '{
        "rules": [],
        "defaults": {
            "effect": "deny"
        }
    }',
    'active',
    '00000000-0000-0000-0000-000000000001'
);
