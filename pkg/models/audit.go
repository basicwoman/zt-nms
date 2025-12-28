package models

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Identity events
	AuditEventIdentityCreate     AuditEventType = "identity.create"
	AuditEventIdentityUpdate     AuditEventType = "identity.update"
	AuditEventIdentityDelete     AuditEventType = "identity.delete"
	AuditEventIdentityAuth       AuditEventType = "identity.auth"
	AuditEventIdentityAuthFailed AuditEventType = "identity.auth_failed"

	// Capability events
	AuditEventCapabilityRequest AuditEventType = "capability.request"
	AuditEventCapabilityIssue   AuditEventType = "capability.issue"
	AuditEventCapabilityUse     AuditEventType = "capability.use"
	AuditEventCapabilityRevoke  AuditEventType = "capability.revoke"
	AuditEventCapabilityExpire  AuditEventType = "capability.expire"

	// Operation events
	AuditEventOperationRequest  AuditEventType = "operation.request"
	AuditEventOperationApprove  AuditEventType = "operation.approve"
	AuditEventOperationExecute  AuditEventType = "operation.execute"
	AuditEventOperationSuccess  AuditEventType = "operation.success"
	AuditEventOperationFailed   AuditEventType = "operation.failed"
	AuditEventOperationDenied   AuditEventType = "operation.denied"

	// Configuration events
	AuditEventConfigCreate   AuditEventType = "config.create"
	AuditEventConfigValidate AuditEventType = "config.validate"
	AuditEventConfigApprove  AuditEventType = "config.approve"
	AuditEventConfigDeploy   AuditEventType = "config.deploy"
	AuditEventConfigApply    AuditEventType = "config.apply"
	AuditEventConfigRollback AuditEventType = "config.rollback"

	// Policy events
	AuditEventPolicyCreate   AuditEventType = "policy.create"
	AuditEventPolicyUpdate   AuditEventType = "policy.update"
	AuditEventPolicyActivate AuditEventType = "policy.activate"
	AuditEventPolicyEvaluate AuditEventType = "policy.evaluate"

	// Device events
	AuditEventDeviceRegister    AuditEventType = "device.register"
	AuditEventDeviceAttest      AuditEventType = "device.attest"
	AuditEventDeviceAttestFail  AuditEventType = "device.attest_failed"
	AuditEventDeviceConnect     AuditEventType = "device.connect"
	AuditEventDeviceDisconnect  AuditEventType = "device.disconnect"

	// Security events
	AuditEventSecurityAlert    AuditEventType = "security.alert"
	AuditEventSecurityIncident AuditEventType = "security.incident"
	AuditEventSecurityViolation AuditEventType = "security.violation"

	// System events
	AuditEventSystemStartup  AuditEventType = "system.startup"
	AuditEventSystemShutdown AuditEventType = "system.shutdown"
	AuditEventSystemConfig   AuditEventType = "system.config"
	AuditEventSystemBackup   AuditEventType = "system.backup"
)

// AuditResult represents the result of an audited action
type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
	AuditResultDenied  AuditResult = "denied"
	AuditResultPending AuditResult = "pending"
)

// AuditSeverity represents the severity of an audit event
type AuditSeverity string

const (
	AuditSeverityDebug    AuditSeverity = "debug"
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditEvent represents an immutable audit log entry
type AuditEvent struct {
	// Identity
	ID       uuid.UUID `json:"id" db:"id"`
	Sequence int64     `json:"sequence" db:"sequence"`

	// Chain
	PrevHash  []byte `json:"prev_hash" db:"prev_hash"`
	EventHash []byte `json:"event_hash" db:"event_hash"`

	// Timestamp
	Timestamp time.Time `json:"timestamp" db:"timestamp"`

	// Event classification
	EventType AuditEventType `json:"event_type" db:"event_type"`
	Severity  AuditSeverity  `json:"severity" db:"severity"`

	// Actor
	ActorID   *uuid.UUID   `json:"actor_id,omitempty" db:"actor_id"`
	ActorType IdentityType `json:"actor_type,omitempty" db:"actor_type"`
	ActorName string       `json:"actor_name,omitempty" db:"actor_name"`

	// Resource
	ResourceType string     `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" db:"resource_id"`
	ResourceName string     `json:"resource_name,omitempty" db:"resource_name"`

	// Action
	Action string      `json:"action" db:"action"`
	Result AuditResult `json:"result" db:"result"`

	// Details
	Details AuditDetails `json:"details,omitempty" db:"details"`

	// References
	CapabilityID *uuid.UUID `json:"capability_id,omitempty" db:"capability_id"`
	OperationID  *uuid.UUID `json:"operation_id,omitempty" db:"operation_id"`
	SessionID    *uuid.UUID `json:"session_id,omitempty" db:"session_id"`

	// Signatures
	OperationSignature []byte `json:"operation_signature,omitempty" db:"operation_signature"`

	// Source
	SourceIP   string `json:"source_ip,omitempty" db:"source_ip"`
	UserAgent  string `json:"user_agent,omitempty" db:"user_agent"`
	RequestID  string `json:"request_id,omitempty" db:"request_id"`
}

// AuditDetails contains detailed information about the event
type AuditDetails struct {
	// Request/Response
	Request  interface{} `json:"request,omitempty"`
	Response interface{} `json:"response,omitempty"`

	// Error information
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`

	// Policy evaluation
	PolicyDecision *PolicyDecision `json:"policy_decision,omitempty"`

	// Configuration changes
	ConfigBefore interface{} `json:"config_before,omitempty"`
	ConfigAfter  interface{} `json:"config_after,omitempty"`
	ConfigDiff   *ConfigDiff `json:"config_diff,omitempty"`

	// Performance metrics
	DurationMs int64 `json:"duration_ms,omitempty"`

	// Additional context
	Context map[string]interface{} `json:"context,omitempty"`

	// Security flags
	SecurityFlags []string `json:"security_flags,omitempty"`
}

// ComputeHash computes the hash for the audit event
func (ae *AuditEvent) ComputeHash() []byte {
	h := sha256.New()

	// Chain link
	if ae.PrevHash != nil {
		h.Write(ae.PrevHash)
	}

	// Timestamp
	binary.Write(h, binary.BigEndian, ae.Timestamp.UnixNano())

	// Event type
	h.Write([]byte(ae.EventType))
	h.Write([]byte(ae.Severity))

	// Actor
	if ae.ActorID != nil {
		h.Write(ae.ActorID[:])
	}
	h.Write([]byte(ae.ActorType))
	h.Write([]byte(ae.ActorName))

	// Resource
	h.Write([]byte(ae.ResourceType))
	if ae.ResourceID != nil {
		h.Write(ae.ResourceID[:])
	}
	h.Write([]byte(ae.ResourceName))

	// Action
	h.Write([]byte(ae.Action))
	h.Write([]byte(ae.Result))

	// Details (serialized)
	detailsJSON, _ := json.Marshal(ae.Details)
	h.Write(detailsJSON)

	// References
	if ae.CapabilityID != nil {
		h.Write(ae.CapabilityID[:])
	}
	if ae.OperationID != nil {
		h.Write(ae.OperationID[:])
	}

	// Source
	h.Write([]byte(ae.SourceIP))
	h.Write([]byte(ae.UserAgent))

	return h.Sum(nil)
}

// Verify verifies the event hash
func (ae *AuditEvent) Verify() bool {
	expectedHash := ae.ComputeHash()
	if len(expectedHash) != len(ae.EventHash) {
		return false
	}
	for i := range expectedHash {
		if expectedHash[i] != ae.EventHash[i] {
			return false
		}
	}
	return true
}

// VerifyChain verifies the chain link to the previous event
func (ae *AuditEvent) VerifyChain(prevEvent *AuditEvent) bool {
	if prevEvent == nil {
		return ae.PrevHash == nil && ae.Sequence == 1
	}
	if ae.Sequence != prevEvent.Sequence+1 {
		return false
	}
	if len(ae.PrevHash) != len(prevEvent.EventHash) {
		return false
	}
	for i := range ae.PrevHash {
		if ae.PrevHash[i] != prevEvent.EventHash[i] {
			return false
		}
	}
	return true
}

// AuditEventBuilder helps build audit events
type AuditEventBuilder struct {
	event *AuditEvent
}

// NewAuditEventBuilder creates a new audit event builder
func NewAuditEventBuilder(eventType AuditEventType) *AuditEventBuilder {
	return &AuditEventBuilder{
		event: &AuditEvent{
			ID:        uuid.New(),
			Timestamp: time.Now().UTC(),
			EventType: eventType,
			Severity:  AuditSeverityInfo,
			Result:    AuditResultSuccess,
			Details:   AuditDetails{},
		},
	}
}

// WithSeverity sets the severity
func (b *AuditEventBuilder) WithSeverity(severity AuditSeverity) *AuditEventBuilder {
	b.event.Severity = severity
	return b
}

// WithActor sets the actor
func (b *AuditEventBuilder) WithActor(id uuid.UUID, actorType IdentityType, name string) *AuditEventBuilder {
	b.event.ActorID = &id
	b.event.ActorType = actorType
	b.event.ActorName = name
	return b
}

// WithResource sets the resource
func (b *AuditEventBuilder) WithResource(resourceType string, id uuid.UUID, name string) *AuditEventBuilder {
	b.event.ResourceType = resourceType
	b.event.ResourceID = &id
	b.event.ResourceName = name
	return b
}

// WithAction sets the action
func (b *AuditEventBuilder) WithAction(action string) *AuditEventBuilder {
	b.event.Action = action
	return b
}

// WithResult sets the result
func (b *AuditEventBuilder) WithResult(result AuditResult) *AuditEventBuilder {
	b.event.Result = result
	return b
}

// WithError sets error information
func (b *AuditEventBuilder) WithError(code, message string) *AuditEventBuilder {
	b.event.Result = AuditResultFailure
	b.event.Details.ErrorCode = code
	b.event.Details.ErrorMessage = message
	return b
}

// WithCapability sets the capability reference
func (b *AuditEventBuilder) WithCapability(id uuid.UUID) *AuditEventBuilder {
	b.event.CapabilityID = &id
	return b
}

// WithOperation sets the operation reference
func (b *AuditEventBuilder) WithOperation(id uuid.UUID) *AuditEventBuilder {
	b.event.OperationID = &id
	return b
}

// WithSource sets the source information
func (b *AuditEventBuilder) WithSource(ip, userAgent, requestID string) *AuditEventBuilder {
	b.event.SourceIP = ip
	b.event.UserAgent = userAgent
	b.event.RequestID = requestID
	return b
}

// WithPolicyDecision sets the policy decision
func (b *AuditEventBuilder) WithPolicyDecision(decision *PolicyDecision) *AuditEventBuilder {
	b.event.Details.PolicyDecision = decision
	return b
}

// WithConfigChange sets the configuration change details
func (b *AuditEventBuilder) WithConfigChange(before, after interface{}, diff *ConfigDiff) *AuditEventBuilder {
	b.event.Details.ConfigBefore = before
	b.event.Details.ConfigAfter = after
	b.event.Details.ConfigDiff = diff
	return b
}

// WithDuration sets the duration
func (b *AuditEventBuilder) WithDuration(durationMs int64) *AuditEventBuilder {
	b.event.Details.DurationMs = durationMs
	return b
}

// WithContext adds context information
func (b *AuditEventBuilder) WithContext(key string, value interface{}) *AuditEventBuilder {
	if b.event.Details.Context == nil {
		b.event.Details.Context = make(map[string]interface{})
	}
	b.event.Details.Context[key] = value
	return b
}

// WithSecurityFlag adds a security flag
func (b *AuditEventBuilder) WithSecurityFlag(flag string) *AuditEventBuilder {
	b.event.Details.SecurityFlags = append(b.event.Details.SecurityFlags, flag)
	return b
}

// Build finalizes and returns the audit event
func (b *AuditEventBuilder) Build(sequence int64, prevHash []byte) *AuditEvent {
	b.event.Sequence = sequence
	b.event.PrevHash = prevHash
	b.event.EventHash = b.event.ComputeHash()
	return b.event
}

// AuditQuery represents a query for audit events
type AuditQuery struct {
	// Time range
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`

	// Filters
	EventTypes    []AuditEventType `json:"event_types,omitempty"`
	Severities    []AuditSeverity  `json:"severities,omitempty"`
	ActorID       *uuid.UUID       `json:"actor_id,omitempty"`
	ActorType     IdentityType     `json:"actor_type,omitempty"`
	ResourceType  string           `json:"resource_type,omitempty"`
	ResourceID    *uuid.UUID       `json:"resource_id,omitempty"`
	Result        AuditResult      `json:"result,omitempty"`
	CapabilityID  *uuid.UUID       `json:"capability_id,omitempty"`
	OperationID   *uuid.UUID       `json:"operation_id,omitempty"`
	SourceIP      string           `json:"source_ip,omitempty"`

	// Pagination
	Limit  int   `json:"limit,omitempty"`
	Offset int64 `json:"offset,omitempty"`

	// Ordering
	OrderBy string `json:"order_by,omitempty"` // timestamp, sequence
	Order   string `json:"order,omitempty"`    // asc, desc
}

// AuditChainVerification represents the result of chain verification
type AuditChainVerification struct {
	Valid         bool      `json:"valid"`
	FirstSequence int64     `json:"first_sequence"`
	LastSequence  int64     `json:"last_sequence"`
	EventCount    int       `json:"event_count"`
	BrokenAt      *int64    `json:"broken_at,omitempty"`
	Error         string    `json:"error,omitempty"`
	VerifiedAt    time.Time `json:"verified_at"`
}

// AuditExport represents exported audit data
type AuditExport struct {
	ExportID    uuid.UUID     `json:"export_id"`
	ExportedAt  time.Time     `json:"exported_at"`
	ExportedBy  uuid.UUID     `json:"exported_by"`
	Query       AuditQuery    `json:"query"`
	Events      []AuditEvent  `json:"events"`
	TotalCount  int           `json:"total_count"`
	ChainValid  bool          `json:"chain_valid"`
	Signature   []byte        `json:"signature"`
}

// AuditRetentionPolicy defines audit log retention rules
type AuditRetentionPolicy struct {
	DefaultRetentionDays int                          `json:"default_retention_days"`
	ByEventType         map[AuditEventType]int       `json:"by_event_type,omitempty"`
	BySeverity          map[AuditSeverity]int        `json:"by_severity,omitempty"`
	ArchiveAfterDays    int                          `json:"archive_after_days,omitempty"`
	ArchiveDestination  string                       `json:"archive_destination,omitempty"`
}

// DefaultAuditRetentionPolicy returns the default retention policy
func DefaultAuditRetentionPolicy() *AuditRetentionPolicy {
	return &AuditRetentionPolicy{
		DefaultRetentionDays: 365,
		BySeverity: map[AuditSeverity]int{
			AuditSeverityCritical: 2555, // 7 years
			AuditSeverityError:    1095, // 3 years
			AuditSeverityWarning:  730,  // 2 years
			AuditSeverityInfo:     365,  // 1 year
			AuditSeverityDebug:    90,   // 3 months
		},
		ByEventType: map[AuditEventType]int{
			AuditEventSecurityIncident:  2555,
			AuditEventSecurityViolation: 2555,
			AuditEventConfigDeploy:      1095,
		},
		ArchiveAfterDays:   180,
		ArchiveDestination: "s3://audit-archive/",
	}
}
