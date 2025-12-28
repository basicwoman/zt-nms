package proxy

import (
	"context"
	"time"
)

// Credentials contains authentication credentials for device connections
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte
	APIKey     string
	Token      string
}

// Connection represents an active connection to a device
type Connection interface {
	// Execute executes an operation on the connection
	Execute(ctx context.Context, operation *Operation) (*OperationResult, error)
	// Close closes the connection
	Close() error
}

// Operation represents an operation to execute on a device
type Operation struct {
	// Action is the operation type (e.g., "get", "set", "get-config", "edit-config")
	Action string
	// ResourcePath is the path to the resource
	ResourcePath string
	// Parameters contains operation-specific parameters
	Parameters map[string]interface{}
	// Data contains the operation payload (for write operations)
	Data interface{}
}

// OperationResult contains the result of an operation
type OperationResult struct {
	// Success indicates whether the operation succeeded
	Success bool
	// Output contains the operation output
	Output string
	// Data contains parsed output data
	Data interface{}
	// Error contains error details if the operation failed
	Error string
	// Duration is how long the operation took
	Duration time.Duration
	// StatusCode is the HTTP status code (for RESTCONF)
	StatusCode int
}
