package models

import (
	"errors"
	"fmt"
)

// Base errors
var (
	// Identity errors
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrIdentityExists        = errors.New("identity already exists")
	ErrIdentityRevoked       = errors.New("identity has been revoked")
	ErrIdentitySuspended     = errors.New("identity has been suspended")
	ErrInvalidIdentityType   = errors.New("invalid identity type")
	ErrInvalidPublicKey      = errors.New("invalid public key")
	ErrInvalidCertificate    = errors.New("invalid certificate")

	// Authentication errors
	ErrAuthenticationFailed  = errors.New("authentication failed")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrMFARequired           = errors.New("MFA verification required")
	ErrMFAFailed             = errors.New("MFA verification failed")
	ErrSessionExpired        = errors.New("session has expired")
	ErrInvalidToken          = errors.New("invalid token")

	// Capability errors
	ErrCapabilityNotFound    = errors.New("capability not found")
	ErrCapabilityExpired     = errors.New("capability has expired")
	ErrCapabilityRevoked     = errors.New("capability has been revoked")
	ErrCapabilityInvalid     = errors.New("capability is invalid")
	ErrCapabilityUsed        = errors.New("capability usage limit reached")
	ErrInsufficientCapability = errors.New("insufficient capability for operation")
	ErrApprovalRequired      = errors.New("approval required for this operation")
	ErrInsufficientApprovals = errors.New("insufficient approvals")
	ErrDelegationNotAllowed  = errors.New("capability delegation not allowed")
	ErrDelegationDepthExceeded = errors.New("delegation depth exceeded")

	// Policy errors
	ErrPolicyNotFound        = errors.New("policy not found")
	ErrPolicyInvalid         = errors.New("policy is invalid")
	ErrPolicyConflict        = errors.New("policy conflict detected")
	ErrAccessDenied          = errors.New("access denied by policy")
	ErrPolicyEvaluationFailed = errors.New("policy evaluation failed")

	// Operation errors
	ErrOperationNotFound     = errors.New("operation not found")
	ErrOperationExpired      = errors.New("operation has expired")
	ErrOperationDenied       = errors.New("operation denied")
	ErrOperationFailed       = errors.New("operation failed")
	ErrOperationTimeout      = errors.New("operation timed out")
	ErrReplayDetected        = errors.New("replay attack detected")
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrInvalidNonce          = errors.New("invalid or reused nonce")
	ErrStateConflict         = errors.New("state conflict - expected state mismatch")
	ErrCommandBlocked        = errors.New("command is blocked")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")

	// Configuration errors
	ErrConfigNotFound        = errors.New("configuration not found")
	ErrConfigInvalid         = errors.New("configuration is invalid")
	ErrConfigValidationFailed = errors.New("configuration validation failed")
	ErrConfigChainBroken     = errors.New("configuration chain integrity broken")
	ErrConfigDeploymentFailed = errors.New("configuration deployment failed")
	ErrConfigRollbackFailed  = errors.New("configuration rollback failed")
	ErrConfigLocked          = errors.New("configuration is locked")

	// Device errors
	ErrDeviceNotFound        = errors.New("device not found")
	ErrDeviceOffline         = errors.New("device is offline")
	ErrDeviceUntrusted       = errors.New("device is not trusted")
	ErrDeviceQuarantined     = errors.New("device is quarantined")
	ErrDeviceConnectionFailed = errors.New("device connection failed")
	ErrDeviceTimeout         = errors.New("device operation timed out")

	// Attestation errors
	ErrAttestationFailed     = errors.New("attestation failed")
	ErrAttestationExpired    = errors.New("attestation has expired")
	ErrMeasurementMismatch   = errors.New("measurement mismatch detected")
	ErrTPMNotAvailable       = errors.New("TPM not available")
	ErrInvalidAttestation    = errors.New("invalid attestation report")

	// Audit errors
	ErrAuditChainBroken      = errors.New("audit chain integrity broken")
	ErrAuditWriteFailed      = errors.New("audit write failed")

	// System errors
	ErrInternalError         = errors.New("internal error")
	ErrNotImplemented        = errors.New("not implemented")
	ErrDatabaseError         = errors.New("database error")
	ErrCryptoError           = errors.New("cryptographic operation failed")
)

// ErrorCode represents a machine-readable error code
type ErrorCode string

const (
	// Identity error codes
	CodeIdentityNotFound      ErrorCode = "IDENTITY_NOT_FOUND"
	CodeIdentityExists        ErrorCode = "IDENTITY_EXISTS"
	CodeIdentityRevoked       ErrorCode = "IDENTITY_REVOKED"
	CodeIdentitySuspended     ErrorCode = "IDENTITY_SUSPENDED"
	CodeInvalidIdentityType   ErrorCode = "INVALID_IDENTITY_TYPE"

	// Authentication error codes
	CodeAuthFailed            ErrorCode = "AUTH_FAILED"
	CodeInvalidCredentials    ErrorCode = "INVALID_CREDENTIALS"
	CodeMFARequired           ErrorCode = "MFA_REQUIRED"
	CodeMFAFailed             ErrorCode = "MFA_FAILED"
	CodeSessionExpired        ErrorCode = "SESSION_EXPIRED"
	CodeInvalidToken          ErrorCode = "INVALID_TOKEN"

	// Capability error codes
	CodeCapabilityNotFound    ErrorCode = "CAPABILITY_NOT_FOUND"
	CodeCapabilityExpired     ErrorCode = "CAPABILITY_EXPIRED"
	CodeCapabilityRevoked     ErrorCode = "CAPABILITY_REVOKED"
	CodeCapabilityInvalid     ErrorCode = "CAPABILITY_INVALID"
	CodeCapabilityUsed        ErrorCode = "CAPABILITY_USED"
	CodeInsufficientCapability ErrorCode = "INSUFFICIENT_CAPABILITY"
	CodeApprovalRequired      ErrorCode = "APPROVAL_REQUIRED"
	CodeInsufficientApprovals ErrorCode = "INSUFFICIENT_APPROVALS"

	// Policy error codes
	CodePolicyNotFound        ErrorCode = "POLICY_NOT_FOUND"
	CodePolicyInvalid         ErrorCode = "POLICY_INVALID"
	CodeAccessDenied          ErrorCode = "ACCESS_DENIED"

	// Operation error codes
	CodeOperationDenied       ErrorCode = "OPERATION_DENIED"
	CodeOperationFailed       ErrorCode = "OPERATION_FAILED"
	CodeOperationTimeout      ErrorCode = "OPERATION_TIMEOUT"
	CodeReplayDetected        ErrorCode = "REPLAY_DETECTED"
	CodeInvalidSignature      ErrorCode = "INVALID_SIGNATURE"
	CodeStateConflict         ErrorCode = "STATE_CONFLICT"
	CodeCommandBlocked        ErrorCode = "COMMAND_BLOCKED"
	CodeRateLimitExceeded     ErrorCode = "RATE_LIMIT_EXCEEDED"

	// Configuration error codes
	CodeConfigNotFound        ErrorCode = "CONFIG_NOT_FOUND"
	CodeConfigInvalid         ErrorCode = "CONFIG_INVALID"
	CodeConfigValidationFailed ErrorCode = "CONFIG_VALIDATION_FAILED"
	CodeConfigChainBroken     ErrorCode = "CONFIG_CHAIN_BROKEN"

	// Device error codes
	CodeDeviceNotFound        ErrorCode = "DEVICE_NOT_FOUND"
	CodeDeviceOffline         ErrorCode = "DEVICE_OFFLINE"
	CodeDeviceUntrusted       ErrorCode = "DEVICE_UNTRUSTED"
	CodeDeviceQuarantined     ErrorCode = "DEVICE_QUARANTINED"

	// Attestation error codes
	CodeAttestationFailed     ErrorCode = "ATTESTATION_FAILED"
	CodeAttestationExpired    ErrorCode = "ATTESTATION_EXPIRED"
	CodeMeasurementMismatch   ErrorCode = "MEASUREMENT_MISMATCH"

	// System error codes
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
	CodeNotImplemented        ErrorCode = "NOT_IMPLEMENTED"
	CodeDatabaseError         ErrorCode = "DATABASE_ERROR"
)

// APIError represents a structured API error
type APIError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Timestamp  int64                  `json:"timestamp,omitempty"`
	InnerError error                  `json:"-"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.InnerError != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.InnerError)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the inner error
func (e *APIError) Unwrap() error {
	return e.InnerError
}

// Is implements errors.Is interface
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// NewAPIError creates a new API error
func NewAPIError(code ErrorCode, message string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
	}
}

// NewAPIErrorWithDetails creates a new API error with details
func NewAPIErrorWithDetails(code ErrorCode, message string, details map[string]interface{}) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// WithInner adds an inner error
func (e *APIError) WithInner(err error) *APIError {
	e.InnerError = err
	return e
}

// WithDetail adds a detail
func (e *APIError) WithDetail(key string, value interface{}) *APIError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithRequestID adds a request ID
func (e *APIError) WithRequestID(requestID string) *APIError {
	e.RequestID = requestID
	return e
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error implements the error interface
func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "validation failed"
	}
	return fmt.Sprintf("validation failed: %s - %s", ve.Errors[0].Field, ve.Errors[0].Message)
}

// Add adds a validation error
func (ve *ValidationErrors) Add(field, message string, value interface{}) {
	ve.Errors = append(ve.Errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// HasErrors returns true if there are validation errors
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// NewValidationErrors creates a new ValidationErrors
func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{
		Errors: make([]ValidationError, 0),
	}
}

// ErrorResponse represents an error response for HTTP APIs
type ErrorResponse struct {
	Success   bool      `json:"success"`
	Error     *APIError `json:"error"`
	RequestID string    `json:"request_id,omitempty"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err *APIError, requestID string) *ErrorResponse {
	return &ErrorResponse{
		Success:   false,
		Error:     err,
		RequestID: requestID,
	}
}

// Helper functions for common errors

// NewIdentityNotFoundError creates an identity not found error
func NewIdentityNotFoundError(identityID string) *APIError {
	return NewAPIErrorWithDetails(CodeIdentityNotFound, "Identity not found", map[string]interface{}{
		"identity_id": identityID,
	})
}

// NewCapabilityExpiredError creates a capability expired error
func NewCapabilityExpiredError(capabilityID string) *APIError {
	return NewAPIErrorWithDetails(CodeCapabilityExpired, "Capability has expired", map[string]interface{}{
		"capability_id": capabilityID,
	})
}

// NewAccessDeniedError creates an access denied error
func NewAccessDeniedError(reason string) *APIError {
	return NewAPIErrorWithDetails(CodeAccessDenied, "Access denied", map[string]interface{}{
		"reason": reason,
	})
}

// NewOperationDeniedError creates an operation denied error
func NewOperationDeniedError(operation string, reason string) *APIError {
	return NewAPIErrorWithDetails(CodeOperationDenied, "Operation denied", map[string]interface{}{
		"operation": operation,
		"reason":    reason,
	})
}

// NewDeviceNotFoundError creates a device not found error
func NewDeviceNotFoundError(deviceID string) *APIError {
	return NewAPIErrorWithDetails(CodeDeviceNotFound, "Device not found", map[string]interface{}{
		"device_id": deviceID,
	})
}

// NewDeviceOfflineError creates a device offline error
func NewDeviceOfflineError(deviceID string) *APIError {
	return NewAPIErrorWithDetails(CodeDeviceOffline, "Device is offline", map[string]interface{}{
		"device_id": deviceID,
	})
}

// NewDeviceUntrustedError creates a device untrusted error
func NewDeviceUntrustedError(deviceID string, reason string) *APIError {
	return NewAPIErrorWithDetails(CodeDeviceUntrusted, "Device is not trusted", map[string]interface{}{
		"device_id": deviceID,
		"reason":    reason,
	})
}

// NewAttestationFailedError creates an attestation failed error
func NewAttestationFailedError(deviceID string, mismatches []AttestationMismatch) *APIError {
	return NewAPIErrorWithDetails(CodeAttestationFailed, "Attestation failed", map[string]interface{}{
		"device_id":  deviceID,
		"mismatches": mismatches,
	})
}

// NewInvalidSignatureError creates an invalid signature error
func NewInvalidSignatureError(context string) *APIError {
	return NewAPIErrorWithDetails(CodeInvalidSignature, "Invalid signature", map[string]interface{}{
		"context": context,
	})
}

// NewReplayDetectedError creates a replay detected error
func NewReplayDetectedError(nonce string) *APIError {
	return NewAPIErrorWithDetails(CodeReplayDetected, "Replay attack detected", map[string]interface{}{
		"nonce": nonce,
	})
}

// NewStateConflictError creates a state conflict error
func NewStateConflictError(expected, actual string) *APIError {
	return NewAPIErrorWithDetails(CodeStateConflict, "State conflict - expected state mismatch", map[string]interface{}{
		"expected": expected,
		"actual":   actual,
	})
}

// NewRateLimitExceededError creates a rate limit exceeded error
func NewRateLimitExceededError(operation string, limit int, period string) *APIError {
	return NewAPIErrorWithDetails(CodeRateLimitExceeded, "Rate limit exceeded", map[string]interface{}{
		"operation": operation,
		"limit":     limit,
		"period":    period,
	})
}
