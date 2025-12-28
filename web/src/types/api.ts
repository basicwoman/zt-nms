// Identity Types
export type IdentityType = 'operator' | 'device' | 'service'
export type IdentityStatus = 'active' | 'suspended' | 'revoked' | 'pending'

export interface Identity {
  id: string
  type: IdentityType
  attributes: OperatorAttributes | DeviceAttributes | ServiceAttributes
  public_key: string
  certificate?: string
  status: IdentityStatus
  created_at: string
  updated_at: string
  created_by?: string
  last_auth?: string
}

export interface OperatorAttributes {
  username: string
  email: string
  groups: string[]
  certifications: string[]
  clearance_level: number
}

export interface DeviceAttributes {
  hostname: string
  vendor: string
  model: string
  serial: string
  location: string
  role: string
  criticality: 'low' | 'medium' | 'high' | 'critical'
  os_type?: string
  os_version?: string
}

export interface ServiceAttributes {
  name: string
  owner: string
  purpose: string
  allowed_operations: string[]
}

// Device Types
export type DeviceTrustStatus = 'trusted' | 'untrusted' | 'verified' | 'unknown' | 'compromised' | 'quarantined'
export type DeviceStatus = 'online' | 'offline' | 'degraded' | 'unknown'
export type ProtocolType = 'ssh' | 'netconf' | 'restconf' | 'snmpv3' | 'gnmi'

export interface Device {
  id: string
  identity_id?: string
  hostname: string
  vendor: string
  model: string
  serial_number: string
  os_type: string
  os_version: string
  role: string
  criticality: string
  location_id?: string
  location_name?: string
  management_ip: string
  status: DeviceStatus
  trust_status: DeviceTrustStatus
  config_sequence: number
  created_at: string
  updated_at: string
  last_seen?: string
  current_config_hash?: string
  supported_protocols?: ProtocolType[]
  metadata?: Record<string, unknown>
}

// Capability Types
export type CapabilityStatus = 'active' | 'expired' | 'revoked' | 'pending_approval'

export interface CapabilityGrant {
  resource: {
    type: string
    id: string
    pattern?: string
  }
  actions: string[]
  constraints?: Record<string, unknown>
  requires_approval?: boolean
  approval_quorum?: number
  approvers?: string[]
}

export interface CapabilityToken {
  id: string
  subject_id: string
  subject_name?: string
  grants: CapabilityGrant[]
  validity: {
    not_before: string
    not_after: string
    max_uses?: number
    renewable?: boolean
  }
  context_requirements?: {
    source_networks?: string[]
    mfa_required?: boolean
    device_posture?: string
  }
  status: CapabilityStatus
  use_count: number
  issued_at: string
  expires_at: string
  revoked_at?: string
  revoked_by?: string
  revocation_reason?: string
}

// Policy Types
export type PolicyType = 'access' | 'config' | 'deployment' | 'security' | 'network'
export type PolicyStatus = 'draft' | 'active' | 'deprecated' | 'archived'
export type PolicyEffect = 'allow' | 'deny' | 'step_up'

export interface PolicyRule {
  name: string
  subjects: Record<string, unknown>
  resources: Record<string, unknown>
  actions: string[]
  conditions?: unknown[]
  effect: PolicyEffect
  obligations?: PolicyObligation[]
}

export interface PolicyObligation {
  type: 'require_approval' | 'notify' | 'log' | 'record_session' | 'time_limit'
  params: Record<string, unknown>
}

export interface PolicyDefinition {
  rules: PolicyRule[]
  defaults?: Record<string, unknown>
  metadata?: Record<string, string>
}

export interface Policy {
  id: string
  name: string
  version: number
  description: string
  type: PolicyType
  definition: PolicyDefinition
  status: PolicyStatus
  effective_from?: string
  effective_until?: string
  created_at: string
  created_by: string
  approved_by?: string
  approval_signature?: string
}

export interface PolicyEvaluationRequest {
  subject_id: string
  resource_type: string
  resource_id: string
  action: string
  context?: Record<string, unknown>
}

export interface PolicyDecision {
  decision: PolicyEffect
  matched_rules: string[]
  obligations: PolicyObligation[]
  constraints?: Record<string, unknown>
}

// Configuration Types
export type DeploymentStatus = 'pending' | 'prepared' | 'committed' | 'verified' | 'failed' | 'rolled_back'

export interface ConfigBlock {
  id: string
  device_id: string
  sequence: number
  prev_hash: string
  merkle_root: string
  block_hash: string
  timestamp: string
  intent?: {
    description: string
    policy_refs: string[]
    change_ticket?: string
  }
  configuration: {
    format: string
    tree: Record<string, unknown>
    vendor_specific?: Record<string, unknown>
  }
  diff?: {
    added: string[]
    modified: string[]
    removed: string[]
  }
  validation: {
    syntax_check: string
    policy_check: string
    security_check: string
    simulation_result?: Record<string, unknown>
  }
  signatures: {
    author: SignatureInfo
    approvers: SignatureInfo[]
    system?: SignatureInfo
  }
  deployment?: {
    status: DeploymentStatus
    applied_at?: string
    device_signature?: string
    device_config_hash?: string
  }
}

export interface SignatureInfo {
  identity: string
  signature: string
  timestamp: string
  role?: string
}

export interface Deployment {
  id: string
  targets: {
    device_id: string
    config_block_id: string
    status: DeploymentStatus
    error?: string
  }[]
  deployment_strategy: 'atomic' | 'rolling' | 'canary'
  overall_status: DeploymentStatus
  created_at: string
  created_by: string
  approved_by?: string
  completed_at?: string
}

// Audit Types
export type AuditEventType = 'auth' | 'identity' | 'capability' | 'policy' | 'config' | 'device' | 'deployment' | 'security'
export type AuditResult = 'success' | 'failure' | 'denied'

export interface AuditEvent {
  id: string
  sequence: number
  prev_hash: string
  event_hash: string
  timestamp: string
  event_type: AuditEventType
  actor_id: string
  actor_name?: string
  actor_type: IdentityType
  resource_type: string
  resource_id: string
  action: string
  result: AuditResult
  details?: Record<string, unknown>
  capability_id?: string
  operation_signature?: string
  source_ip: string
  user_agent?: string
}

// Attestation Types
export type AttestationStatus = 'verified' | 'failed' | 'pending' | 'expired'

export interface AttestationReport {
  device_id: string
  timestamp: string
  measurements: {
    firmware_hash: string
    os_hash: string
    running_config_hash: string
    startup_config_hash: string
    agent_hash: string
    active_processes: string[]
    loaded_modules: string[]
    open_ports: number[]
    network_state: Record<string, unknown>
  }
  pcr_values?: Record<number, string>
  tpm_signature?: string
  software_signature?: string
  status: AttestationStatus
  verified_at?: string
  next_attestation?: string
}

// API Response Types
export interface ApiResponse<T> {
  data: T
  message?: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface ErrorResponse {
  error: {
    code: string
    message: string
    details?: Record<string, unknown>
  }
  request_id: string
}

// Dashboard Stats
export interface DashboardStats {
  devices: {
    total: number
    online: number
    offline: number
    quarantined: number
  }
  identities: {
    total: number
    operators: number
    devices: number
    services: number
    active: number
  }
  capabilities: {
    active: number
    pending_approval: number
    expired_today: number
  }
  policies: {
    total: number
    active: number
    evaluations_today: number
    denials_today: number
  }
  deployments: {
    pending: number
    in_progress: number
    completed_today: number
    failed_today: number
  }
  audit: {
    events_today: number
    security_events: number
    failed_auth: number
  }
}
