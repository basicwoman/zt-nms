package models

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// OperationType represents the type of operation
type OperationType uint8

const (
	OperationTypeRead  OperationType = 1
	OperationTypeWrite OperationType = 2
	OperationTypeExec  OperationType = 3
)

// MessageType represents the type of protocol message
type MessageType uint8

const (
	MessageTypeRequest  MessageType = 1
	MessageTypeResponse MessageType = 2
)

// OperationResult represents the result of an operation
type OperationResultStatus string

const (
	OperationResultSuccess OperationResultStatus = "success"
	OperationResultFailure OperationResultStatus = "failure"
	OperationResultDenied  OperationResultStatus = "denied"
	OperationResultTimeout OperationResultStatus = "timeout"
)

// MessageEnvelope contains protocol metadata
type MessageEnvelope struct {
	ProtocolVersion uint8     `json:"protocol_version" msgpack:"protocol_version"`
	MessageType     MessageType `json:"message_type" msgpack:"message_type"`
	MessageID       uuid.UUID `json:"message_id" msgpack:"message_id"`
	Timestamp       int64     `json:"timestamp" msgpack:"timestamp"`      // Unix timestamp in milliseconds
	Nonce           []byte    `json:"nonce" msgpack:"nonce"`              // 32-byte random nonce
}

// OperationCapability contains capability information for the operation
type OperationCapability struct {
	Token      []byte `json:"token" msgpack:"token"`            // Serialized capability token
	UsageProof []byte `json:"usage_proof" msgpack:"usage_proof"` // Proof of valid usage
}

// Operation contains the operation details
type Operation struct {
	TargetDevice  string                 `json:"target_device" msgpack:"target_device"`
	OperationType OperationType          `json:"operation_type" msgpack:"operation_type"`
	ResourcePath  string                 `json:"resource_path" msgpack:"resource_path"`
	Action        string                 `json:"action" msgpack:"action"`
	Parameters    map[string]interface{} `json:"parameters" msgpack:"parameters"`
	ExpectedState []byte                 `json:"expected_state,omitempty" msgpack:"expected_state"` // Hash of expected current state
}

// OperationApproval represents an approval for an operation
type OperationApproval struct {
	ApproverID   uuid.UUID `json:"approver_id" msgpack:"approver_id"`
	ApprovalTime int64     `json:"approval_time" msgpack:"approval_time"`
	Scope        string    `json:"scope" msgpack:"scope"`
	Signature    []byte    `json:"signature" msgpack:"signature"` // Ed25519 signature
}

// SignedOperation represents a cryptographically signed operation request
type SignedOperation struct {
	Envelope          MessageEnvelope      `json:"envelope" msgpack:"envelope"`
	Capability        OperationCapability  `json:"capability" msgpack:"capability"`
	Operation         Operation            `json:"operation" msgpack:"operation"`
	Approvals         []OperationApproval  `json:"approvals,omitempty" msgpack:"approvals"`
	OperatorSignature []byte               `json:"operator_signature" msgpack:"operator_signature"`
}

// Hash computes the hash of the signed operation (excluding operator signature)
func (so *SignedOperation) Hash() []byte {
	h := sha256.New()

	// Envelope
	h.Write([]byte{so.Envelope.ProtocolVersion})
	h.Write([]byte{byte(so.Envelope.MessageType)})
	h.Write(so.Envelope.MessageID[:])
	binary.Write(h, binary.BigEndian, so.Envelope.Timestamp)
	h.Write(so.Envelope.Nonce)

	// Capability
	h.Write(so.Capability.Token)
	h.Write(so.Capability.UsageProof)

	// Operation
	h.Write([]byte(so.Operation.TargetDevice))
	h.Write([]byte{byte(so.Operation.OperationType)})
	h.Write([]byte(so.Operation.ResourcePath))
	h.Write([]byte(so.Operation.Action))
	paramsJSON, _ := json.Marshal(so.Operation.Parameters)
	h.Write(paramsJSON)
	if so.Operation.ExpectedState != nil {
		h.Write(so.Operation.ExpectedState)
	}

	// Approvals
	for _, approval := range so.Approvals {
		h.Write(approval.ApproverID[:])
		binary.Write(h, binary.BigEndian, approval.ApprovalTime)
		h.Write([]byte(approval.Scope))
		h.Write(approval.Signature)
	}

	return h.Sum(nil)
}

// Sign signs the operation with the operator's private key
func (so *SignedOperation) Sign(privateKey ed25519.PrivateKey) {
	hash := so.Hash()
	so.OperatorSignature = ed25519.Sign(privateKey, hash)
}

// Verify verifies the operator's signature
func (so *SignedOperation) Verify(publicKey ed25519.PublicKey) bool {
	hash := so.Hash()
	return ed25519.Verify(publicKey, hash, so.OperatorSignature)
}

// IsExpired checks if the operation has expired
func (so *SignedOperation) IsExpired(maxAgeMs int64) bool {
	now := time.Now().UnixMilli()
	return now-so.Envelope.Timestamp > maxAgeMs
}

// NewSignedOperation creates a new signed operation
func NewSignedOperation(
	targetDevice string,
	opType OperationType,
	resourcePath string,
	action string,
	parameters map[string]interface{},
	capabilityToken []byte,
	expectedState []byte,
) (*SignedOperation, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return &SignedOperation{
		Envelope: MessageEnvelope{
			ProtocolVersion: 1,
			MessageType:     MessageTypeRequest,
			MessageID:       uuid.New(),
			Timestamp:       time.Now().UnixMilli(),
			Nonce:           nonce,
		},
		Capability: OperationCapability{
			Token: capabilityToken,
		},
		Operation: Operation{
			TargetDevice:  targetDevice,
			OperationType: opType,
			ResourcePath:  resourcePath,
			Action:        action,
			Parameters:    parameters,
			ExpectedState: expectedState,
		},
	}, nil
}

// OperationResult represents the result of executing an operation
type OperationResult struct {
	// Request reference
	RequestID uuid.UUID `json:"request_id" msgpack:"request_id"`

	// Result
	Status      OperationResultStatus  `json:"status" msgpack:"status"`
	Output      interface{}            `json:"output,omitempty" msgpack:"output"`
	Error       string                 `json:"error,omitempty" msgpack:"error"`
	ErrorCode   string                 `json:"error_code,omitempty" msgpack:"error_code"`

	// State
	NewConfigHash []byte `json:"new_config_hash,omitempty" msgpack:"new_config_hash"`

	// Timing
	StartTime    int64 `json:"start_time" msgpack:"start_time"`
	EndTime      int64 `json:"end_time" msgpack:"end_time"`
	DurationMs   int64 `json:"duration_ms" msgpack:"duration_ms"`

	// Device signature
	DeviceID        uuid.UUID `json:"device_id" msgpack:"device_id"`
	DeviceSignature []byte    `json:"device_signature" msgpack:"device_signature"`
}

// Hash computes the hash of the operation result
func (or *OperationResult) Hash() []byte {
	h := sha256.New()

	h.Write(or.RequestID[:])
	h.Write([]byte(or.Status))
	if or.Output != nil {
		outputJSON, _ := json.Marshal(or.Output)
		h.Write(outputJSON)
	}
	h.Write([]byte(or.Error))
	h.Write([]byte(or.ErrorCode))
	if or.NewConfigHash != nil {
		h.Write(or.NewConfigHash)
	}
	binary.Write(h, binary.BigEndian, or.StartTime)
	binary.Write(h, binary.BigEndian, or.EndTime)
	h.Write(or.DeviceID[:])

	return h.Sum(nil)
}

// Sign signs the result with the device's private key
func (or *OperationResult) Sign(privateKey ed25519.PrivateKey) {
	hash := or.Hash()
	or.DeviceSignature = ed25519.Sign(privateKey, hash)
}

// Verify verifies the device's signature
func (or *OperationResult) Verify(publicKey ed25519.PublicKey) bool {
	hash := or.Hash()
	return ed25519.Verify(publicKey, hash, or.DeviceSignature)
}

// SignedResponse represents a complete response message
type SignedResponse struct {
	Envelope MessageEnvelope  `json:"envelope" msgpack:"envelope"`
	Result   OperationResult  `json:"result" msgpack:"result"`
}

// NewOperationResult creates a new operation result
func NewOperationResult(
	requestID uuid.UUID,
	deviceID uuid.UUID,
	status OperationResultStatus,
	output interface{},
	errorMsg string,
	newConfigHash []byte,
	startTime int64,
) *OperationResult {
	endTime := time.Now().UnixMilli()
	return &OperationResult{
		RequestID:     requestID,
		Status:        status,
		Output:        output,
		Error:         errorMsg,
		NewConfigHash: newConfigHash,
		StartTime:     startTime,
		EndTime:       endTime,
		DurationMs:    endTime - startTime,
		DeviceID:      deviceID,
	}
}

// BatchOperation represents a batch of operations to be executed atomically
type BatchOperation struct {
	BatchID     uuid.UUID         `json:"batch_id"`
	Operations  []SignedOperation `json:"operations"`
	Strategy    ExecutionStrategy `json:"strategy"`
	Timeout     int64             `json:"timeout_ms"`
	RollbackOn  RollbackCondition `json:"rollback_on"`
}

// ExecutionStrategy defines how batch operations should be executed
type ExecutionStrategy string

const (
	ExecutionStrategySequential ExecutionStrategy = "sequential"
	ExecutionStrategyParallel   ExecutionStrategy = "parallel"
	ExecutionStrategyAtomic     ExecutionStrategy = "atomic" // 2PC
)

// RollbackCondition defines when to rollback
type RollbackCondition string

const (
	RollbackOnAnyFailure  RollbackCondition = "any_failure"
	RollbackOnAllFailure  RollbackCondition = "all_failure"
	RollbackOnCritical    RollbackCondition = "critical_failure"
	RollbackNever         RollbackCondition = "never"
)

// BatchResult represents the result of a batch operation
type BatchResult struct {
	BatchID   uuid.UUID         `json:"batch_id"`
	Status    OperationResultStatus `json:"status"`
	Results   []OperationResult `json:"results"`
	RolledBack bool             `json:"rolled_back"`
	Duration  int64             `json:"duration_ms"`
}

// CommandFilter defines command filtering rules
type CommandFilter struct {
	BlockedAlways       []string          `json:"blocked_always"`
	RequireConfirmation []string          `json:"require_confirmation"`
	SanitizePatterns    []SanitizePattern `json:"sanitize_patterns"`
	RateLimits          map[string]RateLimit `json:"rate_limits"`
}

// SanitizePattern defines a pattern for sanitizing command output
type SanitizePattern struct {
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// RateLimit defines rate limiting for operations
type RateLimit struct {
	Max int    `json:"max"`
	Per string `json:"per"` // second, minute, hour
}

// DefaultCommandFilter returns default command filtering rules
func DefaultCommandFilter() *CommandFilter {
	return &CommandFilter{
		BlockedAlways: []string{
			"reload",
			"erase",
			"format",
			"delete *",
			"crypto key zeroize",
			"license boot",
			"write erase",
			"init",
		},
		RequireConfirmation: []string{
			"copy running-config startup-config",
			"clear *",
			"debug *",
			"undebug all",
			"shutdown",
		},
		SanitizePatterns: []SanitizePattern{
			{Pattern: `password \S+`, Replace: "password ***"},
			{Pattern: `secret \S+`, Replace: "secret ***"},
			{Pattern: `key \S+`, Replace: "key ***"},
			{Pattern: `community \S+`, Replace: "community ***"},
		},
		RateLimits: map[string]RateLimit{
			"config.*": {Max: 10, Per: "minute"},
			"show.*":   {Max: 100, Per: "minute"},
			"exec.*":   {Max: 50, Per: "minute"},
		},
	}
}
