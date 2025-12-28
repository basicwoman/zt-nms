-- =============================================================================
-- ZT-NMS Comprehensive Seed Data
-- Default credentials: admin / admin
-- =============================================================================

-- =============================================================================
-- OPERATORS (Admin Users)
-- =============================================================================

-- Create admin user identity
INSERT INTO identities (id, type, attributes, public_key, status) VALUES (
    '00000000-0000-0000-0000-000000000002',
    'operator',
    '{
        "username": "admin",
        "email": "admin@zt-nms.local",
        "display_name": "Администратор",
        "role": "admin",
        "groups": ["admins", "network-ops"]
    }',
    E'\\x0000000000000000000000000000000000000000000000000000000000000001',
    'active'
) ON CONFLICT (id) DO NOTHING;

-- Create operator user identity
INSERT INTO identities (id, type, attributes, public_key, status) VALUES (
    '00000000-0000-0000-0000-000000000003',
    'operator',
    '{
        "username": "operator",
        "email": "operator@zt-nms.local",
        "display_name": "Сетевой оператор",
        "role": "operator",
        "groups": ["network-ops"]
    }',
    E'\\x0000000000000000000000000000000000000000000000000000000000000002',
    'active'
) ON CONFLICT (id) DO NOTHING;

-- Create auditor user identity
INSERT INTO identities (id, type, attributes, public_key, status) VALUES (
    '00000000-0000-0000-0000-000000000004',
    'operator',
    '{
        "username": "auditor",
        "email": "auditor@zt-nms.local",
        "display_name": "Аудитор безопасности",
        "role": "auditor",
        "groups": ["auditors"]
    }',
    E'\\x0000000000000000000000000000000000000000000000000000000000000003',
    'active'
) ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- OPERATORS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS operators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'operator',
    last_login TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);
CREATE INDEX IF NOT EXISTS idx_operators_identity ON operators(identity_id);

-- Insert operators (password: admin for all)
-- bcrypt hash of 'admin': $2a$10$2ie19beJQwnQGb1a.OmKz.9uJgHjWNeejaL06VgdJvOmI6n9iu0Ym
INSERT INTO operators (id, identity_id, username, password_hash, email, role) VALUES
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002', 'admin', '$2a$10$2ie19beJQwnQGb1a.OmKz.9uJgHjWNeejaL06VgdJvOmI6n9iu0Ym', 'admin@zt-nms.local', 'admin'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000003', 'operator', '$2a$10$2ie19beJQwnQGb1a.OmKz.9uJgHjWNeejaL06VgdJvOmI6n9iu0Ym', 'operator@zt-nms.local', 'operator'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000004', 'auditor', '$2a$10$2ie19beJQwnQGb1a.OmKz.9uJgHjWNeejaL06VgdJvOmI6n9iu0Ym', 'auditor@zt-nms.local', 'auditor')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_operator ON refresh_tokens(operator_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- =============================================================================
-- LOCATIONS (Data Centers / Sites)
-- =============================================================================

INSERT INTO locations (id, name, type, parent_id, address, metadata) VALUES
    ('10000000-0000-0000-0000-000000000001', 'EVE-NG Лаборатория', 'datacenter', NULL, '{"city": "Виртуальная лаборатория", "country": "Local"}', '{"environment": "lab", "tier": "development"}'),
    ('10000000-0000-0000-0000-000000000002', 'Ядро сети', 'zone', '10000000-0000-0000-0000-000000000001', '{}', '{"vlan_range": "1-100"}'),
    ('10000000-0000-0000-0000-000000000003', 'Уровень распределения', 'zone', '10000000-0000-0000-0000-000000000001', '{}', '{"vlan_range": "101-200"}'),
    ('10000000-0000-0000-0000-000000000004', 'Уровень доступа', 'zone', '10000000-0000-0000-0000-000000000001', '{}', '{"vlan_range": "201-500"}'),
    ('10000000-0000-0000-0000-000000000005', 'DMZ', 'zone', '10000000-0000-0000-0000-000000000001', '{}', '{"security_zone": "dmz"}'),
    ('10000000-0000-0000-0000-000000000006', 'Серверная ферма', 'zone', '10000000-0000-0000-0000-000000000001', '{}', '{"security_zone": "internal"}')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- DEVICE IDENTITIES (Cisco & PfSense)
-- =============================================================================

-- Cisco Core Router 1
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000001', 'device',
    '{"hostname": "core-rtr-01", "vendor": "Cisco", "model": "CSR1000V", "role": "core-router"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000001', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- Cisco Core Router 2
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000002', 'device',
    '{"hostname": "core-rtr-02", "vendor": "Cisco", "model": "CSR1000V", "role": "core-router"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000002', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- Cisco Distribution Switch 1
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000003', 'device',
    '{"hostname": "dist-sw-01", "vendor": "Cisco", "model": "Catalyst 9300", "role": "distribution-switch"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000003', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- Cisco Distribution Switch 2
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000004', 'device',
    '{"hostname": "dist-sw-02", "vendor": "Cisco", "model": "Catalyst 9300", "role": "distribution-switch"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000004', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- Cisco Access Switches
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000005', 'device',
    '{"hostname": "access-sw-01", "vendor": "Cisco", "model": "Catalyst 2960X", "role": "access-switch"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000005', 'active', '00000000-0000-0000-0000-000000000002'),
    ('20000000-0000-0000-0000-000000000006', 'device',
    '{"hostname": "access-sw-02", "vendor": "Cisco", "model": "Catalyst 2960X", "role": "access-switch"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000006', 'active', '00000000-0000-0000-0000-000000000002'),
    ('20000000-0000-0000-0000-000000000007', 'device',
    '{"hostname": "access-sw-03", "vendor": "Cisco", "model": "Catalyst 2960X", "role": "access-switch"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000007', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- PfSense Firewalls
INSERT INTO identities (id, type, attributes, public_key, status, created_by) VALUES
    ('20000000-0000-0000-0000-000000000010', 'device',
    '{"hostname": "fw-edge-01", "vendor": "Netgate", "model": "pfSense", "role": "edge-firewall"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000010', 'active', '00000000-0000-0000-0000-000000000002'),
    ('20000000-0000-0000-0000-000000000011', 'device',
    '{"hostname": "fw-dmz-01", "vendor": "Netgate", "model": "pfSense", "role": "dmz-firewall"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000011', 'active', '00000000-0000-0000-0000-000000000002'),
    ('20000000-0000-0000-0000-000000000012', 'device',
    '{"hostname": "fw-internal-01", "vendor": "Netgate", "model": "pfSense", "role": "internal-firewall"}',
    E'\\x1000000000000000000000000000000000000000000000000000000000000012', 'active', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- DEVICES TABLE
-- =============================================================================

-- Cisco Core Routers
INSERT INTO devices (id, identity_id, hostname, vendor, model, serial_number, os_type, os_version, role, criticality, location_id, management_ip, management_port, management_protocol, status, trust_status, tags, metadata) VALUES
    ('30000000-0000-0000-0000-000000000001', '20000000-0000-0000-0000-000000000001', 'core-rtr-01', 'Cisco', 'CSR1000V', 'CSR1000V-SN001', 'IOS-XE', '17.3.4a', 'core-router', 'critical', '10000000-0000-0000-0000-000000000002', '10.0.0.1', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'core', 'router', 'ospf', 'bgp'], '{"interfaces": ["GigabitEthernet1", "GigabitEthernet2", "GigabitEthernet3"], "protocols": ["OSPF", "BGP", "EIGRP"]}'),
    ('30000000-0000-0000-0000-000000000002', '20000000-0000-0000-0000-000000000002', 'core-rtr-02', 'Cisco', 'CSR1000V', 'CSR1000V-SN002', 'IOS-XE', '17.3.4a', 'core-router', 'critical', '10000000-0000-0000-0000-000000000002', '10.0.0.2', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'core', 'router', 'ospf', 'bgp'], '{"interfaces": ["GigabitEthernet1", "GigabitEthernet2", "GigabitEthernet3"], "protocols": ["OSPF", "BGP", "EIGRP"]}')
ON CONFLICT (id) DO NOTHING;

-- Cisco Distribution Switches
INSERT INTO devices (id, identity_id, hostname, vendor, model, serial_number, os_type, os_version, role, criticality, location_id, management_ip, management_port, management_protocol, status, trust_status, tags, metadata) VALUES
    ('30000000-0000-0000-0000-000000000003', '20000000-0000-0000-0000-000000000003', 'dist-sw-01', 'Cisco', 'Catalyst 9300', 'C9300-SN001', 'IOS-XE', '17.6.3', 'distribution-switch', 'high', '10000000-0000-0000-0000-000000000003', '10.0.1.1', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'distribution', 'switch', 'vtp', 'stp'], '{"stack_members": 2, "ports": 48, "uplink_ports": 4}'),
    ('30000000-0000-0000-0000-000000000004', '20000000-0000-0000-0000-000000000004', 'dist-sw-02', 'Cisco', 'Catalyst 9300', 'C9300-SN002', 'IOS-XE', '17.6.3', 'distribution-switch', 'high', '10000000-0000-0000-0000-000000000003', '10.0.1.2', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'distribution', 'switch', 'vtp', 'stp'], '{"stack_members": 2, "ports": 48, "uplink_ports": 4}')
ON CONFLICT (id) DO NOTHING;

-- Cisco Access Switches
INSERT INTO devices (id, identity_id, hostname, vendor, model, serial_number, os_type, os_version, role, criticality, location_id, management_ip, management_port, management_protocol, status, trust_status, tags, metadata) VALUES
    ('30000000-0000-0000-0000-000000000005', '20000000-0000-0000-0000-000000000005', 'access-sw-01', 'Cisco', 'Catalyst 2960X', 'C2960X-SN001', 'IOS', '15.2(7)E4', 'access-switch', 'medium', '10000000-0000-0000-0000-000000000004', '10.0.2.1', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'access', 'switch', 'poe'], '{"ports": 24, "poe_budget": 370}'),
    ('30000000-0000-0000-0000-000000000006', '20000000-0000-0000-0000-000000000006', 'access-sw-02', 'Cisco', 'Catalyst 2960X', 'C2960X-SN002', 'IOS', '15.2(7)E4', 'access-switch', 'medium', '10000000-0000-0000-0000-000000000004', '10.0.2.2', 22, 'ssh', 'online', 'trusted', ARRAY['cisco', 'access', 'switch', 'poe'], '{"ports": 24, "poe_budget": 370}'),
    ('30000000-0000-0000-0000-000000000007', '20000000-0000-0000-0000-000000000007', 'access-sw-03', 'Cisco', 'Catalyst 2960X', 'C2960X-SN003', 'IOS', '15.2(7)E4', 'access-switch', 'medium', '10000000-0000-0000-0000-000000000004', '10.0.2.3', 22, 'ssh', 'degraded', 'untrusted', ARRAY['cisco', 'access', 'switch', 'poe'], '{"ports": 24, "poe_budget": 370, "issue": "config_drift_detected"}')
ON CONFLICT (id) DO NOTHING;

-- PfSense Firewalls
INSERT INTO devices (id, identity_id, hostname, vendor, model, serial_number, os_type, os_version, role, criticality, location_id, management_ip, management_port, management_protocol, status, trust_status, tags, metadata) VALUES
    ('30000000-0000-0000-0000-000000000010', '20000000-0000-0000-0000-000000000010', 'fw-edge-01', 'Netgate', 'pfSense CE', 'PFSENSE-SN001', 'FreeBSD', '2.7.2', 'edge-firewall', 'critical', '10000000-0000-0000-0000-000000000005', '10.0.100.1', 443, 'https', 'online', 'trusted', ARRAY['pfsense', 'firewall', 'edge', 'vpn', 'nat'], '{"interfaces": ["wan", "lan", "opt1", "opt2"], "packages": ["pfBlockerNG", "Suricata", "HAProxy"]}'),
    ('30000000-0000-0000-0000-000000000011', '20000000-0000-0000-0000-000000000011', 'fw-dmz-01', 'Netgate', 'pfSense CE', 'PFSENSE-SN002', 'FreeBSD', '2.7.2', 'dmz-firewall', 'critical', '10000000-0000-0000-0000-000000000005', '10.0.100.2', 443, 'https', 'online', 'trusted', ARRAY['pfsense', 'firewall', 'dmz'], '{"interfaces": ["wan", "dmz", "internal"], "packages": ["Suricata"]}'),
    ('30000000-0000-0000-0000-000000000012', '20000000-0000-0000-0000-000000000012', 'fw-internal-01', 'Netgate', 'pfSense CE', 'PFSENSE-SN003', 'FreeBSD', '2.7.2', 'internal-firewall', 'high', '10000000-0000-0000-0000-000000000006', '10.0.100.3', 443, 'https', 'online', 'trusted', ARRAY['pfsense', 'firewall', 'internal', 'segmentation'], '{"interfaces": ["servers", "workstations", "iot"], "packages": ["pfBlockerNG"]}')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- DEVICE GROUPS
-- =============================================================================

INSERT INTO device_groups (id, name, description, type, device_ids, metadata) VALUES
    ('40000000-0000-0000-0000-000000000001', 'Ядро инфраструктуры', 'Корневые маршрутизаторы и критические устройства', 'static',
     ARRAY['30000000-0000-0000-0000-000000000001'::uuid, '30000000-0000-0000-0000-000000000002'::uuid],
     '{"criticality": "critical", "change_window": "maintenance_only"}'),
    ('40000000-0000-0000-0000-000000000002', 'Уровень распределения', 'Коммутаторы распределения', 'static',
     ARRAY['30000000-0000-0000-0000-000000000003'::uuid, '30000000-0000-0000-0000-000000000004'::uuid],
     '{"criticality": "high"}'),
    ('40000000-0000-0000-0000-000000000003', 'Уровень доступа', 'Коммутаторы доступа', 'static',
     ARRAY['30000000-0000-0000-0000-000000000005'::uuid, '30000000-0000-0000-0000-000000000006'::uuid, '30000000-0000-0000-0000-000000000007'::uuid],
     '{"criticality": "medium"}'),
    ('40000000-0000-0000-0000-000000000004', 'Межсетевые экраны', 'Все межсетевые экраны', 'static',
     ARRAY['30000000-0000-0000-0000-000000000010'::uuid, '30000000-0000-0000-0000-000000000011'::uuid, '30000000-0000-0000-0000-000000000012'::uuid],
     '{"criticality": "critical", "vendor": "Netgate"}'),
    ('40000000-0000-0000-0000-000000000005', 'Устройства Cisco', 'Всё сетевое оборудование Cisco', 'dynamic',
     ARRAY[]::uuid[],
     '{"query": {"vendor": "Cisco"}}'),
    ('40000000-0000-0000-0000-000000000006', 'Недоверенные устройства', 'Устройства с проблемами доверия', 'dynamic',
     ARRAY[]::uuid[],
     '{"query": {"trust_status": "untrusted"}}')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- POLICIES
-- =============================================================================

-- Network Access Policy
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000001', 'network-admin-access', 'access',
    'Политика полного доступа для сетевых администраторов',
    '{
        "rules": [
            {
                "name": "allow-admins-full-access",
                "effect": "allow",
                "subjects": {"groups": ["admins", "network-ops"]},
                "resources": {"types": ["device", "config"]},
                "actions": ["read", "write", "execute", "configure"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"}
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- Read-Only Policy for Auditors
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000002', 'auditor-readonly', 'access',
    'Политика доступа только на чтение для аудиторов',
    '{
        "rules": [
            {
                "name": "allow-auditors-read",
                "effect": "allow",
                "subjects": {"groups": ["auditors"]},
                "resources": {"types": ["device", "config", "audit", "policy"]},
                "actions": ["read", "view", "export"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"}
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- Firewall Change Policy
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000003', 'firewall-change-control', 'config',
    'Политика контроля изменений межсетевых экранов',
    '{
        "rules": [
            {
                "name": "firewall-config-approval",
                "effect": "allow",
                "subjects": {"groups": ["admins"]},
                "resources": {"types": ["firewall"]},
                "actions": ["configure", "deploy"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"}
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- Core Infrastructure Protection Policy
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000004', 'core-infrastructure-protection', 'access',
    'Ограничения доступа к ядру инфраструктуры',
    '{
        "rules": [
            {
                "name": "core-infra-access",
                "effect": "allow",
                "subjects": {"groups": ["admins"]},
                "resources": {"types": ["core-device"]},
                "actions": ["read", "write", "execute"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"}
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- Network Segmentation Policy
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000005', 'network-segmentation', 'network',
    'Политика сегментации и изоляции сети',
    '{
        "rules": [
            {
                "name": "segment-management",
                "effect": "allow",
                "subjects": {"groups": ["admins"]},
                "resources": {"types": ["vlan"]},
                "actions": ["manage"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"},
        "metadata": {
            "segments": "management:10,servers:20,workstations:30,iot:40,dmz:100,guest:200"
        }
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- Deployment Strategy Policy
INSERT INTO policies (id, name, type, description, definition, status, created_by, effective_from) VALUES
    ('50000000-0000-0000-0000-000000000006', 'canary-deployment', 'deployment',
    'Канареечная стратегия развертывания для изменений конфигурации',
    '{
        "rules": [
            {
                "name": "canary-deploy-rule",
                "effect": "allow",
                "subjects": {"groups": ["admins", "network-ops"]},
                "resources": {"types": ["config"]},
                "actions": ["deploy"],
                "conditions": []
            }
        ],
        "defaults": {"effect": "deny"},
        "metadata": {
            "strategy": "canary",
            "canary_percentage": "10",
            "validation_period_minutes": "30"
        }
    }',
    'active', '00000000-0000-0000-0000-000000000002', NOW())
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- CAPABILITIES (Access Tokens)
-- =============================================================================

-- Admin capability token
INSERT INTO capabilities (id, token_id, issuer, subject_id, subject_hash, grants, validity, issuer_signature) VALUES
    ('60000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001',
    'zt-nms-system', '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    '[
        {"resource": "*", "actions": ["*"], "constraints": {}},
        {"resource": "device:*", "actions": ["read", "write", "execute", "configure"], "constraints": {}},
        {"resource": "policy:*", "actions": ["read", "write", "create", "delete"], "constraints": {}},
        {"resource": "audit:*", "actions": ["read", "export"], "constraints": {}}
    ]',
    '{"not_before": "2024-01-01T00:00:00Z", "not_after": "2025-12-31T23:59:59Z", "max_uses": null}',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (id) DO NOTHING;

-- Operator limited capability
INSERT INTO capabilities (id, token_id, issuer, subject_id, subject_hash, grants, validity, issuer_signature) VALUES
    ('60000000-0000-0000-0000-000000000002', '60000000-0000-0000-0000-000000000002',
    'zt-nms-system', '00000000-0000-0000-0000-000000000003',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    '[
        {"resource": "device:*", "actions": ["read", "execute"], "constraints": {"device_groups": ["Access Layer"]}},
        {"resource": "config:*", "actions": ["read", "validate"], "constraints": {}},
        {"resource": "audit:*", "actions": ["read"], "constraints": {"time_range": "7d"}}
    ]',
    '{"not_before": "2024-01-01T00:00:00Z", "not_after": "2025-12-31T23:59:59Z", "max_uses": 1000}',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (id) DO NOTHING;

-- Auditor read-only capability
INSERT INTO capabilities (id, token_id, issuer, subject_id, subject_hash, grants, validity, issuer_signature) VALUES
    ('60000000-0000-0000-0000-000000000003', '60000000-0000-0000-0000-000000000003',
    'zt-nms-system', '00000000-0000-0000-0000-000000000004',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    '[
        {"resource": "device:*", "actions": ["read"], "constraints": {}},
        {"resource": "policy:*", "actions": ["read"], "constraints": {}},
        {"resource": "audit:*", "actions": ["read", "export", "verify"], "constraints": {}},
        {"resource": "capability:*", "actions": ["read"], "constraints": {}}
    ]',
    '{"not_before": "2024-01-01T00:00:00Z", "not_after": "2025-12-31T23:59:59Z", "max_uses": null}',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- AUDIT EVENTS (Sample history)
-- =============================================================================

INSERT INTO audit_events (id, event_hash, event_type, severity, actor_id, actor_type, actor_name, resource_type, resource_id, resource_name, action, result, details, source_ip) VALUES
    ('70000000-0000-0000-0000-000000000001', E'\\x0001', 'identity.auth', 'info', '00000000-0000-0000-0000-000000000002', 'operator', 'admin', 'identity', '00000000-0000-0000-0000-000000000002', 'admin', 'login', 'success', '{"method": "password", "mfa": false}', '10.0.0.100'),
    ('70000000-0000-0000-0000-000000000002', E'\\x0002', 'device.config.change', 'warning', '00000000-0000-0000-0000-000000000002', 'operator', 'admin', 'device', '30000000-0000-0000-0000-000000000001', 'core-rtr-01', 'configure', 'success', '{"changes": ["interface GigabitEthernet1 description Updated"]}', '10.0.0.100'),
    ('70000000-0000-0000-0000-000000000003', E'\\x0003', 'policy.create', 'info', '00000000-0000-0000-0000-000000000002', 'operator', 'admin', 'policy', '50000000-0000-0000-0000-000000000001', 'network-admin-access', 'create', 'success', '{}', '10.0.0.100'),
    ('70000000-0000-0000-0000-000000000004', E'\\x0004', 'device.attestation', 'info', NULL, 'system', 'zt-nms', 'device', '30000000-0000-0000-0000-000000000001', 'core-rtr-01', 'attest', 'success', '{"trust_score": 98}', NULL),
    ('70000000-0000-0000-0000-000000000005', E'\\x0005', 'device.attestation', 'warning', NULL, 'system', 'zt-nms', 'device', '30000000-0000-0000-0000-000000000007', 'access-sw-03', 'attest', 'failure', '{"trust_score": 45, "issues": ["config_drift", "unexpected_processes"]}', NULL),
    ('70000000-0000-0000-0000-000000000006', E'\\x0006', 'capability.grant', 'info', '00000000-0000-0000-0000-000000000002', 'operator', 'admin', 'capability', '60000000-0000-0000-0000-000000000002', NULL, 'grant', 'success', '{"subject": "operator", "permissions": ["device:read", "device:execute"]}', '10.0.0.100'),
    ('70000000-0000-0000-0000-000000000007', E'\\x0007', 'device.connect', 'info', '00000000-0000-0000-0000-000000000003', 'operator', 'operator', 'device', '30000000-0000-0000-0000-000000000005', 'access-sw-01', 'ssh_connect', 'success', '{"protocol": "ssh", "duration_seconds": 300}', '10.0.0.101'),
    ('70000000-0000-0000-0000-000000000008', E'\\x0008', 'security.alert', 'critical', NULL, 'system', 'zt-nms', 'device', '30000000-0000-0000-0000-000000000007', 'access-sw-03', 'security_violation', 'detected', '{"type": "config_drift", "severity": "high", "details": "Unauthorized VLAN changes detected"}', NULL)
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- CONFIG BLOCKS (Sample configurations)
-- =============================================================================

INSERT INTO config_blocks (id, device_id, sequence, block_hash, configuration, author_id, author_signature, deployment_status, applied_at) VALUES
    ('80000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000001', 1,
    E'\\x0001',
    '{
        "hostname": "core-rtr-01",
        "domain": "zt-nms.local",
        "interfaces": [
            {"name": "GigabitEthernet1", "description": "Uplink to ISP", "ip": "203.0.113.1/30", "status": "up"},
            {"name": "GigabitEthernet2", "description": "To Distribution", "ip": "10.0.0.1/30", "status": "up"},
            {"name": "GigabitEthernet3", "description": "Management", "ip": "10.0.0.1/24", "status": "up"}
        ],
        "routing": {
            "ospf": {"process_id": 1, "router_id": "10.0.0.1", "networks": ["10.0.0.0/8"]},
            "bgp": {"asn": 65001, "neighbors": [{"ip": "203.0.113.2", "remote_as": 65000}]}
        },
        "services": {
            "ssh": {"enabled": true, "version": 2},
            "snmp": {"enabled": true, "community": "public", "version": "2c"}
        }
    }',
    '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'applied', NOW() - INTERVAL '7 days')
ON CONFLICT (id) DO NOTHING;

INSERT INTO config_blocks (id, device_id, sequence, block_hash, configuration, author_id, author_signature, deployment_status, applied_at) VALUES
    ('80000000-0000-0000-0000-000000000002', '30000000-0000-0000-0000-000000000010', 1,
    E'\\x0002',
    '{
        "hostname": "fw-edge-01",
        "interfaces": [
            {"name": "wan", "ip": "dhcp", "gateway": true},
            {"name": "lan", "ip": "10.0.0.254/24", "status": "up"},
            {"name": "opt1", "ip": "10.0.100.254/24", "description": "DMZ", "status": "up"}
        ],
        "firewall": {
            "default_policy": "block",
            "rules": [
                {"id": 1, "action": "pass", "interface": "lan", "source": "lan net", "destination": "any", "port": "80,443"},
                {"id": 2, "action": "pass", "interface": "wan", "source": "any", "destination": "opt1 net", "port": "80,443"},
                {"id": 3, "action": "block", "interface": "wan", "source": "any", "destination": "lan net", "log": true}
            ]
        },
        "nat": {
            "outbound": [{"interface": "wan", "source": "lan net", "translation": "interface address"}],
            "port_forwards": [{"interface": "wan", "port": 443, "destination": "10.0.100.10:443"}]
        },
        "vpn": {
            "openvpn": {"enabled": true, "port": 1194, "protocol": "udp"},
            "ipsec": {"enabled": true}
        },
        "packages": {
            "pfblockerng": {"enabled": true, "dnsbl": true},
            "suricata": {"enabled": true, "interfaces": ["wan"]}
        }
    }',
    '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'applied', NOW() - INTERVAL '3 days')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- NETWORK TOPOLOGY DATA (for EVE-NG integration)
-- =============================================================================

CREATE TABLE IF NOT EXISTS network_topology (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    topology_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES identities(id)
);

INSERT INTO network_topology (id, name, description, topology_data, created_by) VALUES
    ('90000000-0000-0000-0000-000000000001', 'EVE-NG Lab Topology',
    'Лаборатория Zero Trust Network с устройствами Cisco и pfSense',
    '{
        "nodes": [
            {"id": "core-rtr-01", "type": "router", "vendor": "cisco", "model": "csr1000v", "x": 400, "y": 100},
            {"id": "core-rtr-02", "type": "router", "vendor": "cisco", "model": "csr1000v", "x": 600, "y": 100},
            {"id": "dist-sw-01", "type": "switch", "vendor": "cisco", "model": "viosl2", "x": 300, "y": 250},
            {"id": "dist-sw-02", "type": "switch", "vendor": "cisco", "model": "viosl2", "x": 700, "y": 250},
            {"id": "access-sw-01", "type": "switch", "vendor": "cisco", "model": "viosl2", "x": 200, "y": 400},
            {"id": "access-sw-02", "type": "switch", "vendor": "cisco", "model": "viosl2", "x": 400, "y": 400},
            {"id": "access-sw-03", "type": "switch", "vendor": "cisco", "model": "viosl2", "x": 600, "y": 400},
            {"id": "fw-edge-01", "type": "firewall", "vendor": "pfsense", "model": "pfsense", "x": 500, "y": 50},
            {"id": "fw-dmz-01", "type": "firewall", "vendor": "pfsense", "model": "pfsense", "x": 800, "y": 200},
            {"id": "fw-internal-01", "type": "firewall", "vendor": "pfsense", "model": "pfsense", "x": 100, "y": 300}
        ],
        "links": [
            {"source": "fw-edge-01", "target": "core-rtr-01", "type": "ethernet"},
            {"source": "fw-edge-01", "target": "core-rtr-02", "type": "ethernet"},
            {"source": "core-rtr-01", "target": "core-rtr-02", "type": "ethernet"},
            {"source": "core-rtr-01", "target": "dist-sw-01", "type": "ethernet"},
            {"source": "core-rtr-02", "target": "dist-sw-02", "type": "ethernet"},
            {"source": "dist-sw-01", "target": "dist-sw-02", "type": "trunk"},
            {"source": "dist-sw-01", "target": "access-sw-01", "type": "trunk"},
            {"source": "dist-sw-01", "target": "access-sw-02", "type": "trunk"},
            {"source": "dist-sw-02", "target": "access-sw-02", "type": "trunk"},
            {"source": "dist-sw-02", "target": "access-sw-03", "type": "trunk"},
            {"source": "core-rtr-01", "target": "fw-dmz-01", "type": "ethernet"},
            {"source": "dist-sw-01", "target": "fw-internal-01", "type": "ethernet"}
        ],
        "vlans": [
            {"id": 10, "name": "Management", "subnet": "10.0.0.0/24"},
            {"id": 20, "name": "Servers", "subnet": "10.0.10.0/24"},
            {"id": 30, "name": "Workstations", "subnet": "10.0.20.0/24"},
            {"id": 40, "name": "IoT", "subnet": "10.0.30.0/24"},
            {"id": 100, "name": "DMZ", "subnet": "10.0.100.0/24"},
            {"id": 200, "name": "Guest", "subnet": "10.0.200.0/24"}
        ],
        "eve_ng": {
            "lab_name": "zt-nms-lab",
            "version": "5.0",
            "images": {
                "csr1000v": "csr1000v-universalk9.17.03.04a-serial",
                "viosl2": "viosl2-adventerprisek9-m.ssa.high_iron_20200929",
                "pfsense": "pfsense-2.7.2"
            }
        }
    }',
    '00000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- SERVICE IDENTITIES (for microservices)
-- =============================================================================

INSERT INTO identities (id, type, attributes, public_key, status) VALUES
    ('00000000-0000-0000-0000-000000000010', 'service',
    '{"name": "config-service", "owner": "system", "purpose": "Configuration management service"}',
    E'\\x2000000000000000000000000000000000000000000000000000000000000010', 'active'),
    ('00000000-0000-0000-0000-000000000011', 'service',
    '{"name": "attestation-service", "owner": "system", "purpose": "Device attestation service"}',
    E'\\x2000000000000000000000000000000000000000000000000000000000000011', 'active'),
    ('00000000-0000-0000-0000-000000000012', 'service',
    '{"name": "audit-service", "owner": "system", "purpose": "Audit logging service"}',
    E'\\x2000000000000000000000000000000000000000000000000000000000000012', 'active'),
    ('00000000-0000-0000-0000-000000000013', 'service',
    '{"name": "policy-engine", "owner": "system", "purpose": "Policy evaluation engine"}',
    E'\\x2000000000000000000000000000000000000000000000000000000000000013', 'active')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- EXPECTED MEASUREMENTS (for attestation)
-- =============================================================================

INSERT INTO expected_measurements (device_id, firmware_hash, os_hash, expected_pcrs, allowed_processes, min_os_version, min_firmware_version, updated_by) VALUES
    ('30000000-0000-0000-0000-000000000001',
    E'\\xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    E'\\x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    '{"pcr0": "abc123", "pcr1": "def456", "pcr7": "789xyz"}',
    ARRAY['sshd', 'snmpd', 'bgpd', 'ospfd', 'zebra'],
    '17.3.0',
    '17.3.4',
    '00000000-0000-0000-0000-000000000002'),
    ('30000000-0000-0000-0000-000000000010',
    E'\\xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    E'\\x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba',
    '{}',
    ARRAY['php-fpm', 'nginx', 'unbound', 'suricata', 'dpinger'],
    '2.7.0',
    '2.7.2',
    '00000000-0000-0000-0000-000000000002')
ON CONFLICT (device_id) DO NOTHING;

-- =============================================================================
-- CONFIG BACKUPS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS config_backups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    backup_type VARCHAR(50) NOT NULL DEFAULT 'manual',
    configuration TEXT NOT NULL,
    hash BYTEA,
    created_by UUID REFERENCES identities(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_config_backups_device ON config_backups(device_id);
CREATE INDEX IF NOT EXISTS idx_config_backups_created ON config_backups(created_at DESC);

-- =============================================================================
-- REAL CISCO IOS-XE CONFIGURATION FOR CORE ROUTERS
-- =============================================================================

-- Core Router 1 full config
INSERT INTO config_blocks (id, device_id, sequence, block_hash, configuration, author_id, author_signature, deployment_status, applied_at) VALUES
    ('80000000-0000-0000-0000-000000000003', '30000000-0000-0000-0000-000000000001', 2,
    E'\\x0003',
    '{
        "hostname": "core-rtr-01",
        "domain": "zt-nms.local",
        "version": "17.3.4a",
        "services": {
            "timestamps": {"debug": "datetime msec", "log": "datetime msec"},
            "password_encryption": true
        },
        "interfaces": [
            {"name": "GigabitEthernet1", "description": "WAN Uplink", "ip_address": "203.0.113.1/30", "status": "up"},
            {"name": "GigabitEthernet2", "description": "Core Interconnect", "ip_address": "10.0.0.1/30", "status": "up", "ospf": {"area": 0}},
            {"name": "GigabitEthernet3", "description": "To Distribution", "ip_address": "10.0.1.1/24", "status": "up", "hsrp": {"group": 1, "priority": 110, "vip": "10.0.1.254"}},
            {"name": "Loopback0", "ip_address": "10.255.255.1/32"}
        ],
        "routing": {
            "ospf": {"process_id": 1, "router_id": "10.255.255.1", "networks": ["10.0.0.0/8"]},
            "bgp": {"asn": 65001, "neighbors": [{"ip": "203.0.113.2", "remote_as": 65000}]}
        },
        "security": {"ssh_version": 2, "login_block": {"attempts": 3, "within": 60}}
    }',
    '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'applied', NOW() - INTERVAL '1 day')
ON CONFLICT (id) DO NOTHING;

-- Distribution Switch 1 config
INSERT INTO config_blocks (id, device_id, sequence, block_hash, configuration, author_id, author_signature, deployment_status, applied_at) VALUES
    ('80000000-0000-0000-0000-000000000005', '30000000-0000-0000-0000-000000000003', 1,
    E'\\x0005',
    '{
        "hostname": "dist-sw-01",
        "vlans": [
            {"id": 10, "name": "Management"},
            {"id": 20, "name": "Servers"},
            {"id": 30, "name": "Workstations"},
            {"id": 100, "name": "DMZ"}
        ],
        "interfaces": [
            {"name": "GigabitEthernet0/1", "description": "Uplink to core-rtr-01", "mode": "routed", "ip_address": "10.0.1.11/24"},
            {"name": "GigabitEthernet0/2", "description": "Cross-connect", "mode": "trunk", "allowed_vlans": "10,20,30,100"},
            {"name": "Vlan10", "ip_address": "10.0.10.2/24", "hsrp": {"group": 10, "vip": "10.0.10.1"}}
        ],
        "spanning_tree": {"mode": "rapid-pvst", "priority": 4096}
    }',
    '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'applied', NOW() - INTERVAL '3 days')
ON CONFLICT (id) DO NOTHING;

-- pfSense Edge Firewall full config
INSERT INTO config_blocks (id, device_id, sequence, block_hash, configuration, author_id, author_signature, deployment_status, applied_at) VALUES
    ('80000000-0000-0000-0000-000000000007', '30000000-0000-0000-0000-000000000010', 2,
    E'\\x0007',
    '{
        "hostname": "fw-edge-01",
        "version": "2.7.2-RELEASE",
        "interfaces": {
            "wan": {"device": "em0", "type": "dhcp", "block_private": true, "block_bogons": true},
            "lan": {"device": "em1", "ip": "10.0.0.254/24"},
            "dmz": {"device": "em2", "ip": "10.0.100.254/24"}
        },
        "firewall_rules": [
            {"interface": "lan", "action": "pass", "source": "lan net", "destination": "any", "description": "Allow LAN to Any"},
            {"interface": "wan", "action": "pass", "protocol": "tcp", "destination_port": "80,443", "destination": "dmz net", "description": "Allow HTTP/HTTPS to DMZ"},
            {"interface": "wan", "action": "block", "log": true, "description": "Block all other WAN"}
        ],
        "nat": {"outbound_mode": "automatic", "port_forwards": [{"port": 443, "target": "10.0.100.10"}]},
        "vpn": {"openvpn": {"enabled": true, "port": 1194, "tunnel": "10.8.0.0/24"}},
        "packages": {"pfblockerng": {"enabled": true}, "suricata": {"enabled": true, "interfaces": ["wan"]}}
    }',
    '00000000-0000-0000-0000-000000000002',
    E'\\x0000000000000000000000000000000000000000000000000000000000000000',
    'applied', NOW() - INTERVAL '1 day')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- SAMPLE CONFIG BACKUPS
-- =============================================================================

INSERT INTO config_backups (id, device_id, backup_type, configuration, hash, created_by, created_at, description) VALUES
    ('a0000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000001', 'scheduled',
    '! Backup of core-rtr-01
hostname core-rtr-01
interface GigabitEthernet1
 ip address 203.0.113.1 255.255.255.252
!',
    E'\\xaabbccdd',
    '00000000-0000-0000-0000-000000000002',
    NOW() - INTERVAL '7 days',
    'Weekly scheduled backup'),
    ('a0000000-0000-0000-0000-000000000002', '30000000-0000-0000-0000-000000000010', 'pre-change',
    '<?xml version="1.0"?><pfsense><hostname>fw-edge-01</hostname></pfsense>',
    E'\\xeeff0011',
    '00000000-0000-0000-0000-000000000002',
    NOW() - INTERVAL '2 days',
    'Backup before firewall rule change')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- DASHBOARD STATS VIEW
-- =============================================================================

CREATE OR REPLACE VIEW dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM devices) as total_devices,
    (SELECT COUNT(*) FROM devices WHERE status = 'online') as online_devices,
    (SELECT COUNT(*) FROM devices WHERE status = 'offline') as offline_devices,
    (SELECT COUNT(*) FROM devices WHERE status = 'degraded') as degraded_devices,
    (SELECT COUNT(*) FROM devices WHERE trust_status = 'trusted') as trusted_devices,
    (SELECT COUNT(*) FROM devices WHERE trust_status = 'untrusted') as untrusted_devices,
    (SELECT COUNT(*) FROM identities WHERE type = 'operator' AND status = 'active') as active_operators,
    (SELECT COUNT(*) FROM policies WHERE status = 'active') as active_policies,
    (SELECT COUNT(*) FROM capabilities WHERE revoked = FALSE) as active_capabilities,
    (SELECT COUNT(*) FROM audit_events WHERE timestamp > NOW() - INTERVAL '24 hours') as events_24h,
    (SELECT COUNT(*) FROM audit_events WHERE severity = 'critical' AND timestamp > NOW() - INTERVAL '24 hours') as critical_events_24h;
