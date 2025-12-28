-- Zero Trust NMS Database Schema
-- Version: 1.0.0

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- IDENTITIES
-- =============================================================================

CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(20) NOT NULL CHECK (type IN ('operator', 'device', 'service')),
    attributes JSONB NOT NULL DEFAULT '{}',
    public_key BYTEA NOT NULL,
    certificate BYTEA,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES identities(id)
);

CREATE INDEX idx_identities_type ON identities(type);
CREATE INDEX idx_identities_status ON identities(status);
CREATE INDEX idx_identities_public_key ON identities(public_key);
CREATE INDEX idx_identities_attributes ON identities USING GIN(attributes);
CREATE INDEX idx_identities_created_at ON identities(created_at);

-- Operator-specific index
CREATE INDEX idx_identities_username ON identities((attributes->>'username')) 
    WHERE type = 'operator';

-- Device-specific index
CREATE INDEX idx_identities_hostname ON identities((attributes->>'hostname')) 
    WHERE type = 'device';

-- =============================================================================
-- CAPABILITIES
-- =============================================================================

CREATE TABLE capabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id UUID UNIQUE NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    issuer VARCHAR(255) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    subject_id UUID NOT NULL REFERENCES identities(id),
    subject_hash BYTEA NOT NULL,
    grants JSONB NOT NULL DEFAULT '[]',
    validity JSONB NOT NULL,
    context_requirements JSONB,
    delegation JSONB,
    parent_token_id UUID REFERENCES capabilities(token_id),
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    approvals JSONB DEFAULT '[]',
    issuer_signature BYTEA NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES identities(id),
    revocation_reason VARCHAR(500)
);

CREATE INDEX idx_capabilities_subject ON capabilities(subject_id);
CREATE INDEX idx_capabilities_token_id ON capabilities(token_id);
CREATE INDEX idx_capabilities_parent ON capabilities(parent_token_id);
CREATE INDEX idx_capabilities_validity ON capabilities USING GIN(validity);
CREATE INDEX idx_capabilities_issued_at ON capabilities(issued_at);
CREATE INDEX idx_capabilities_revoked ON capabilities(revoked) WHERE revoked = TRUE;

-- =============================================================================
-- POLICIES
-- =============================================================================

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    type VARCHAR(50) NOT NULL CHECK (type IN ('access', 'config', 'deployment', 'network')),
    definition JSONB NOT NULL,
    compiled BYTEA,
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
    effective_from TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES identities(id),
    approved_by UUID REFERENCES identities(id),
    approval_signature BYTEA
);

CREATE INDEX idx_policies_name ON policies(name);
CREATE INDEX idx_policies_type ON policies(type);
CREATE INDEX idx_policies_status ON policies(status);
CREATE INDEX idx_policies_effective ON policies(effective_from, effective_until);

CREATE TABLE policy_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES identities(id),
    change_log TEXT,
    UNIQUE(policy_id, version)
);

CREATE INDEX idx_policy_versions_policy ON policy_versions(policy_id);

-- =============================================================================
-- DEVICES
-- =============================================================================

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID UNIQUE REFERENCES identities(id),
    hostname VARCHAR(255) NOT NULL,
    vendor VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    asset_tag VARCHAR(100),
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    firmware_version VARCHAR(50),
    role VARCHAR(50) NOT NULL DEFAULT 'access-switch',
    criticality VARCHAR(20) NOT NULL DEFAULT 'medium',
    tags TEXT[] DEFAULT '{}',
    location_id UUID,
    rack_position VARCHAR(50),
    management_ip INET NOT NULL,
    management_port INTEGER DEFAULT 22,
    management_protocol VARCHAR(20) NOT NULL DEFAULT 'ssh',
    supports_agent BOOLEAN DEFAULT FALSE,
    agent_version VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    trust_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    last_seen TIMESTAMPTZ,
    last_attestation TIMESTAMPTZ,
    current_config_sequence BIGINT DEFAULT 0,
    current_config_hash BYTEA,
    startup_config_hash BYTEA,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_hostname ON devices(hostname);
CREATE INDEX idx_devices_management_ip ON devices(management_ip);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_trust_status ON devices(trust_status);
CREATE INDEX idx_devices_role ON devices(role);
CREATE INDEX idx_devices_criticality ON devices(criticality);
CREATE INDEX idx_devices_tags ON devices USING GIN(tags);
CREATE INDEX idx_devices_location ON devices(location_id);

CREATE TABLE device_credentials (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol VARCHAR(20) NOT NULL,
    encrypted_data BYTEA NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    last_rotated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (device_id, protocol)
);

CREATE TABLE device_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'static' CHECK (type IN ('static', 'dynamic')),
    device_ids UUID[] DEFAULT '{}',
    query JSONB,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_groups_name ON device_groups(name);
CREATE INDEX idx_device_groups_device_ids ON device_groups USING GIN(device_ids);

-- =============================================================================
-- CONFIGURATIONS
-- =============================================================================

CREATE TABLE config_blocks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    sequence BIGINT NOT NULL,
    prev_hash BYTEA,
    merkle_root BYTEA,
    block_hash BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    intent JSONB,
    configuration JSONB NOT NULL,
    diff JSONB,
    validation JSONB,
    author_id UUID NOT NULL REFERENCES identities(id),
    author_signature BYTEA NOT NULL,
    approvals JSONB DEFAULT '[]',
    system_signature BYTEA,
    deployment_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    device_signature BYTEA,
    applied_at TIMESTAMPTZ,
    device_config_hash BYTEA,
    UNIQUE(device_id, sequence)
);

CREATE INDEX idx_config_blocks_device ON config_blocks(device_id);
CREATE INDEX idx_config_blocks_sequence ON config_blocks(device_id, sequence DESC);
CREATE INDEX idx_config_blocks_timestamp ON config_blocks(timestamp);
CREATE INDEX idx_config_blocks_status ON config_blocks(deployment_status);
CREATE INDEX idx_config_blocks_author ON config_blocks(author_id);
CREATE INDEX idx_config_blocks_hash ON config_blocks(block_hash);

-- =============================================================================
-- ATTESTATION
-- =============================================================================

CREATE TABLE attestation_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    type VARCHAR(20) NOT NULL CHECK (type IN ('tpm', 'software', 'remote')),
    measurements JSONB NOT NULL,
    pcr_values JSONB,
    tpm_signature BYTEA,
    aik_cert BYTEA,
    software_signature BYTEA,
    nonce BYTEA NOT NULL,
    quote_data BYTEA
);

CREATE INDEX idx_attestation_device ON attestation_reports(device_id);
CREATE INDEX idx_attestation_timestamp ON attestation_reports(timestamp);

CREATE TABLE expected_measurements (
    device_id UUID PRIMARY KEY REFERENCES devices(id),
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
    min_firmware_version VARCHAR(50),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES identities(id)
);

CREATE TABLE attestation_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id),
    report_id UUID NOT NULL REFERENCES attestation_reports(id),
    status VARCHAR(20) NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature_valid BOOLEAN NOT NULL,
    nonce_valid BOOLEAN NOT NULL,
    measurements_valid BOOLEAN NOT NULL,
    pcrs_valid BOOLEAN,
    mismatches JSONB,
    warnings TEXT[],
    recommended_action VARCHAR(100)
);

CREATE INDEX idx_attestation_results_device ON attestation_results(device_id);
CREATE INDEX idx_attestation_results_status ON attestation_results(status);

-- =============================================================================
-- AUDIT
-- =============================================================================

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence BIGINT NOT NULL,
    prev_hash BYTEA,
    event_hash BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    actor_id UUID REFERENCES identities(id),
    actor_type VARCHAR(20),
    actor_name VARCHAR(255),
    resource_type VARCHAR(50),
    resource_id UUID,
    resource_name VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    result VARCHAR(20) NOT NULL,
    details JSONB DEFAULT '{}',
    capability_id UUID,
    operation_id UUID,
    session_id UUID,
    operation_signature BYTEA,
    source_ip INET,
    user_agent TEXT,
    request_id VARCHAR(100)
);

CREATE INDEX idx_audit_sequence ON audit_events(sequence);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_severity ON audit_events(severity);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX idx_audit_result ON audit_events(result);
CREATE INDEX idx_audit_capability ON audit_events(capability_id);
CREATE INDEX idx_audit_operation ON audit_events(operation_id);
CREATE INDEX idx_audit_source_ip ON audit_events(source_ip);

-- Partitioning for audit events (by month)
-- In production, use pg_partman or similar

-- =============================================================================
-- OPERATIONS
-- =============================================================================

CREATE TABLE operations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id UUID UNIQUE NOT NULL,
    protocol_version INTEGER NOT NULL DEFAULT 1,
    message_type INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    nonce BYTEA NOT NULL,
    capability_token_id UUID REFERENCES capabilities(token_id),
    target_device UUID NOT NULL REFERENCES devices(id),
    operation_type INTEGER NOT NULL,
    resource_path VARCHAR(500),
    action VARCHAR(100),
    parameters JSONB,
    expected_state BYTEA,
    approvals JSONB DEFAULT '[]',
    operator_signature BYTEA NOT NULL,
    operator_id UUID NOT NULL REFERENCES identities(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_operations_message_id ON operations(message_id);
CREATE INDEX idx_operations_device ON operations(target_device);
CREATE INDEX idx_operations_operator ON operations(operator_id);
CREATE INDEX idx_operations_status ON operations(status);
CREATE INDEX idx_operations_timestamp ON operations(timestamp);

CREATE TABLE operation_results (
    operation_id UUID PRIMARY KEY REFERENCES operations(id),
    status VARCHAR(20) NOT NULL,
    output TEXT,
    error TEXT,
    error_code VARCHAR(50),
    new_config_hash BYTEA,
    start_time BIGINT NOT NULL,
    end_time BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id),
    device_signature BYTEA
);

-- =============================================================================
-- SESSIONS
-- =============================================================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operator_id UUID NOT NULL REFERENCES identities(id),
    device_id UUID NOT NULL REFERENCES devices(id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    protocol VARCHAR(20) NOT NULL,
    source_ip INET,
    commands_count INTEGER DEFAULT 0,
    recording_path VARCHAR(500)
);

CREATE INDEX idx_sessions_operator ON sessions(operator_id);
CREATE INDEX idx_sessions_device ON sessions(device_id);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_started ON sessions(started_at);

CREATE TABLE session_commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    command TEXT NOT NULL,
    output TEXT,
    duration_ms INTEGER,
    success BOOLEAN
);

CREATE INDEX idx_session_commands_session ON session_commands(session_id);
CREATE INDEX idx_session_commands_timestamp ON session_commands(timestamp);

-- =============================================================================
-- LOCATIONS
-- =============================================================================

CREATE TABLE locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    parent_id UUID REFERENCES locations(id),
    address JSONB,
    coordinates JSONB,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_locations_name ON locations(name);
CREATE INDEX idx_locations_type ON locations(type);
CREATE INDEX idx_locations_parent ON locations(parent_id);

-- =============================================================================
-- NONCES (for replay protection)
-- =============================================================================

CREATE TABLE nonces (
    nonce BYTEA PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_nonces_expires ON nonces(expires_at);

-- Function to clean up expired nonces
CREATE OR REPLACE FUNCTION cleanup_expired_nonces() RETURNS void AS $$
BEGIN
    DELETE FROM nonces WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_identities_updated
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_devices_updated
    BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_policies_updated
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_device_groups_updated
    BEFORE UPDATE ON device_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Audit sequence trigger
CREATE SEQUENCE audit_sequence_seq START 1;

CREATE OR REPLACE FUNCTION set_audit_sequence()
RETURNS TRIGGER AS $$
BEGIN
    NEW.sequence = nextval('audit_sequence_seq');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_audit_sequence
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION set_audit_sequence();

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert system identity
INSERT INTO identities (id, type, attributes, public_key, status) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'service',
    '{"name": "system", "owner": "system", "purpose": "System service identity"}',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'active'
);

-- Insert default policies
INSERT INTO policies (id, name, type, description, definition, status, created_by) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default-deny',
    'access',
    'Default deny policy',
    '{"rules": [], "defaults": {"effect": "deny"}}',
    'active',
    '00000000-0000-0000-0000-000000000001'
);
