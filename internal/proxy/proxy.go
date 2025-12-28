package proxy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/capability"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// Proxy handles device communication
type Proxy struct {
	adapters        map[models.ProtocolType]ProtocolAdapter
	capabilityIssuer *capability.Issuer
	commandFilter   *models.CommandFilter
	sessionRecorder SessionRecorder
	logger          *zap.Logger
	mu              sync.RWMutex
	connections     map[uuid.UUID]*DeviceConnection
	rateLimiter     RateLimiter
}

// ProtocolAdapter adapts operations to device protocols
type ProtocolAdapter interface {
	Connect(ctx context.Context, device *models.Device, credentials []byte) error
	Disconnect(ctx context.Context, device *models.Device) error
	Execute(ctx context.Context, device *models.Device, command string) (*ExecutionResult, error)
	GetConfig(ctx context.Context, device *models.Device, section string) (string, error)
	SetConfig(ctx context.Context, device *models.Device, commands []string) error
	IsConnected(device *models.Device) bool
}

// SessionRecorder records session activity
type SessionRecorder interface {
	StartSession(deviceID, operatorID uuid.UUID) (uuid.UUID, error)
	RecordCommand(sessionID uuid.UUID, command string, output string, duration time.Duration) error
	EndSession(sessionID uuid.UUID) error
}

// RateLimiter provides rate limiting
type RateLimiter interface {
	Allow(key string, limit int, period time.Duration) bool
}

// DeviceConnection represents an active device connection
type DeviceConnection struct {
	DeviceID       uuid.UUID
	Protocol       models.ProtocolType
	ConnectedAt    time.Time
	LastActivityAt time.Time
	SessionID      uuid.UUID
	OperatorID     *uuid.UUID
}

// ExecutionResult contains the result of command execution
type ExecutionResult struct {
	Output     string
	Error      string
	Duration   time.Duration
	ExitCode   int
	Truncated  bool
}

// NewProxy creates a new device proxy
func NewProxy(capabilityIssuer *capability.Issuer, logger *zap.Logger) *Proxy {
	return &Proxy{
		adapters:         make(map[models.ProtocolType]ProtocolAdapter),
		capabilityIssuer: capabilityIssuer,
		commandFilter:    models.DefaultCommandFilter(),
		logger:           logger,
		connections:      make(map[uuid.UUID]*DeviceConnection),
	}
}

// RegisterAdapter registers a protocol adapter
func (p *Proxy) RegisterAdapter(protocol models.ProtocolType, adapter ProtocolAdapter) {
	p.adapters[protocol] = adapter
}

// SetSessionRecorder sets the session recorder
func (p *Proxy) SetSessionRecorder(recorder SessionRecorder) {
	p.sessionRecorder = recorder
}

// SetRateLimiter sets the rate limiter
func (p *Proxy) SetRateLimiter(limiter RateLimiter) {
	p.rateLimiter = limiter
}

// SetCommandFilter sets the command filter
func (p *Proxy) SetCommandFilter(filter *models.CommandFilter) {
	p.commandFilter = filter
}

// ExecuteOperation executes a signed operation on a device
func (p *Proxy) ExecuteOperation(ctx context.Context, op *models.SignedOperation, device *models.Device, operatorKey ed25519.PublicKey) (*models.OperationResult, error) {
	startTime := time.Now().UnixMilli()

	// Verify operator signature
	if !op.Verify(operatorKey) {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "invalid operator signature")
	}

	// Check timestamp and nonce (replay protection)
	if op.IsExpired(300000) { // 5 minutes max age
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "operation expired")
	}

	// Deserialize and verify capability token
	token, err := p.capabilityIssuer.Deserialize(op.Capability.Token)
	if err != nil {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "invalid capability token")
	}

	if err := p.capabilityIssuer.Verify(ctx, token); err != nil {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, err.Error())
	}

	// Check if operation is allowed by capability
	action := p.operationTypeToAction(op.Operation.OperationType)
	if !token.Allows(action, "device", device.ID.String()) {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "operation not allowed by capability")
	}

	// Check rate limits
	if p.rateLimiter != nil {
		rateLimitKey := fmt.Sprintf("%s:%s", token.SubjectID.String(), string(action))
		if !p.rateLimiter.Allow(rateLimitKey, 100, time.Minute) {
			return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "rate limit exceeded")
		}
	}

	// Get adapter for device protocol
	adapter, ok := p.adapters[device.ManagementProtocol]
	if !ok {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "unsupported protocol")
	}

	// Execute based on operation type
	var result *models.OperationResult
	switch op.Operation.OperationType {
	case models.OperationTypeRead:
		result, err = p.executeRead(ctx, op, device, adapter, startTime)
	case models.OperationTypeWrite:
		result, err = p.executeWrite(ctx, op, device, adapter, token, startTime)
	case models.OperationTypeExec:
		result, err = p.executeCommand(ctx, op, device, adapter, startTime)
	default:
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, "unknown operation type")
	}

	if err != nil {
		return p.failedResult(op.Envelope.MessageID, device.ID, startTime, err.Error())
	}

	// Record capability usage
	p.capabilityIssuer.Use(ctx, token, action, "device", device.ID.String())

	return result, nil
}

// executeRead executes a read operation
func (p *Proxy) executeRead(ctx context.Context, op *models.SignedOperation, device *models.Device, adapter ProtocolAdapter, startTime int64) (*models.OperationResult, error) {
	section := op.Operation.ResourcePath
	if section == "" {
		section = "running-config"
	}

	config, err := adapter.GetConfig(ctx, device, section)
	if err != nil {
		return nil, err
	}

	// Sanitize output
	sanitized := p.sanitizeOutput(config)

	return &models.OperationResult{
		RequestID:  op.Envelope.MessageID,
		Status:     models.OperationResultSuccess,
		Output:     sanitized,
		StartTime:  startTime,
		EndTime:    time.Now().UnixMilli(),
		DurationMs: time.Now().UnixMilli() - startTime,
		DeviceID:   device.ID,
	}, nil
}

// executeWrite executes a write operation
func (p *Proxy) executeWrite(ctx context.Context, op *models.SignedOperation, device *models.Device, adapter ProtocolAdapter, token *models.CapabilityToken, startTime int64) (*models.OperationResult, error) {
	// Get commands from parameters
	commandsRaw, ok := op.Operation.Parameters["commands"]
	if !ok {
		return nil, fmt.Errorf("commands parameter required")
	}

	commands, ok := commandsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("commands must be an array")
	}

	// Convert to string slice and filter
	cmdStrings := make([]string, 0, len(commands))
	for _, cmd := range commands {
		cmdStr, ok := cmd.(string)
		if !ok {
			continue
		}

		// Check command filter
		if p.isBlocked(cmdStr) {
			return nil, fmt.Errorf("command blocked: %s", cmdStr)
		}

		// Check constraints from capability
		grant := token.GetGrantForResource("device", device.ID.String())
		if grant != nil && grant.Constraints != nil {
			if len(grant.Constraints.DeniedCommands) > 0 {
				for _, denied := range grant.Constraints.DeniedCommands {
					if strings.Contains(cmdStr, denied) {
						return nil, fmt.Errorf("command denied by capability: %s", cmdStr)
					}
				}
			}
		}

		cmdStrings = append(cmdStrings, cmdStr)
	}

	if err := adapter.SetConfig(ctx, device, cmdStrings); err != nil {
		return nil, err
	}

	return &models.OperationResult{
		RequestID:  op.Envelope.MessageID,
		Status:     models.OperationResultSuccess,
		Output:     fmt.Sprintf("Applied %d commands", len(cmdStrings)),
		StartTime:  startTime,
		EndTime:    time.Now().UnixMilli(),
		DurationMs: time.Now().UnixMilli() - startTime,
		DeviceID:   device.ID,
	}, nil
}

// executeCommand executes a command
func (p *Proxy) executeCommand(ctx context.Context, op *models.SignedOperation, device *models.Device, adapter ProtocolAdapter, startTime int64) (*models.OperationResult, error) {
	command := op.Operation.Action
	if command == "" {
		cmdRaw, ok := op.Operation.Parameters["command"]
		if ok {
			command, _ = cmdRaw.(string)
		}
	}

	if command == "" {
		return nil, fmt.Errorf("command required")
	}

	// Check command filter
	if p.isBlocked(command) {
		return nil, fmt.Errorf("command blocked: %s", command)
	}

	// Check if confirmation required
	if p.requiresConfirmation(command) {
		confirmed, ok := op.Operation.Parameters["confirmed"]
		if !ok || confirmed != true {
			return nil, fmt.Errorf("command requires confirmation: %s", command)
		}
	}

	execResult, err := adapter.Execute(ctx, device, command)
	if err != nil {
		return nil, err
	}

	// Sanitize output
	sanitized := p.sanitizeOutput(execResult.Output)

	// Record in session
	if p.sessionRecorder != nil {
		conn := p.getConnection(device.ID)
		if conn != nil {
			p.sessionRecorder.RecordCommand(conn.SessionID, command, sanitized, execResult.Duration)
		}
	}

	result := &models.OperationResult{
		RequestID:  op.Envelope.MessageID,
		Status:     models.OperationResultSuccess,
		Output:     sanitized,
		StartTime:  startTime,
		EndTime:    time.Now().UnixMilli(),
		DurationMs: time.Now().UnixMilli() - startTime,
		DeviceID:   device.ID,
	}

	if execResult.Error != "" {
		result.Status = models.OperationResultFailure
		result.Error = execResult.Error
	}

	return result, nil
}

// isBlocked checks if a command is blocked
func (p *Proxy) isBlocked(command string) bool {
	cmdLower := strings.ToLower(command)
	for _, blocked := range p.commandFilter.BlockedAlways {
		if strings.HasSuffix(blocked, "*") {
			prefix := strings.TrimSuffix(blocked, "*")
			if strings.HasPrefix(cmdLower, strings.ToLower(prefix)) {
				return true
			}
		} else if strings.ToLower(blocked) == cmdLower {
			return true
		}
	}
	return false
}

// requiresConfirmation checks if a command requires confirmation
func (p *Proxy) requiresConfirmation(command string) bool {
	cmdLower := strings.ToLower(command)
	for _, confirm := range p.commandFilter.RequireConfirmation {
		if strings.HasSuffix(confirm, "*") {
			prefix := strings.TrimSuffix(confirm, "*")
			if strings.HasPrefix(cmdLower, strings.ToLower(prefix)) {
				return true
			}
		} else if strings.ToLower(confirm) == cmdLower {
			return true
		}
	}
	return false
}

// sanitizeOutput sanitizes command output
func (p *Proxy) sanitizeOutput(output string) string {
	result := output
	for _, pattern := range p.commandFilter.SanitizePatterns {
		re, err := regexp.Compile("(?i)" + pattern.Pattern)
		if err != nil {
			continue
		}
		result = re.ReplaceAllString(result, pattern.Replace)
	}
	return result
}

// operationTypeToAction converts operation type to action
func (p *Proxy) operationTypeToAction(opType models.OperationType) models.ActionType {
	switch opType {
	case models.OperationTypeRead:
		return models.ActionConfigRead
	case models.OperationTypeWrite:
		return models.ActionConfigWrite
	case models.OperationTypeExec:
		return models.ActionExecCommand
	default:
		return models.ActionConfigRead
	}
}

// failedResult creates a failed operation result
func (p *Proxy) failedResult(requestID uuid.UUID, deviceID uuid.UUID, startTime int64, errMsg string) (*models.OperationResult, error) {
	return &models.OperationResult{
		RequestID:  requestID,
		Status:     models.OperationResultFailure,
		Error:      errMsg,
		StartTime:  startTime,
		EndTime:    time.Now().UnixMilli(),
		DurationMs: time.Now().UnixMilli() - startTime,
		DeviceID:   deviceID,
	}, nil
}

// Connect establishes a connection to a device
func (p *Proxy) Connect(ctx context.Context, device *models.Device, credentials []byte, operatorID *uuid.UUID) error {
	adapter, ok := p.adapters[device.ManagementProtocol]
	if !ok {
		return fmt.Errorf("unsupported protocol: %s", device.ManagementProtocol)
	}

	if err := adapter.Connect(ctx, device, credentials); err != nil {
		return err
	}

	// Start session
	var sessionID uuid.UUID
	if p.sessionRecorder != nil && operatorID != nil {
		var err error
		sessionID, err = p.sessionRecorder.StartSession(device.ID, *operatorID)
		if err != nil {
			p.logger.Warn("Failed to start session recording", zap.Error(err))
		}
	}

	// Track connection
	p.mu.Lock()
	p.connections[device.ID] = &DeviceConnection{
		DeviceID:       device.ID,
		Protocol:       device.ManagementProtocol,
		ConnectedAt:    time.Now(),
		LastActivityAt: time.Now(),
		SessionID:      sessionID,
		OperatorID:     operatorID,
	}
	p.mu.Unlock()

	p.logger.Info("Connected to device",
		zap.String("device_id", device.ID.String()),
		zap.String("protocol", string(device.ManagementProtocol)),
	)

	return nil
}

// Disconnect closes a connection to a device
func (p *Proxy) Disconnect(ctx context.Context, device *models.Device) error {
	adapter, ok := p.adapters[device.ManagementProtocol]
	if !ok {
		return fmt.Errorf("unsupported protocol: %s", device.ManagementProtocol)
	}

	// End session
	p.mu.Lock()
	conn, exists := p.connections[device.ID]
	if exists {
		if p.sessionRecorder != nil && conn.SessionID != uuid.Nil {
			p.sessionRecorder.EndSession(conn.SessionID)
		}
		delete(p.connections, device.ID)
	}
	p.mu.Unlock()

	if err := adapter.Disconnect(ctx, device); err != nil {
		return err
	}

	p.logger.Info("Disconnected from device",
		zap.String("device_id", device.ID.String()),
	)

	return nil
}

// getConnection gets the connection for a device
func (p *Proxy) getConnection(deviceID uuid.UUID) *DeviceConnection {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connections[deviceID]
}

// GetConnections returns all active connections
func (p *Proxy) GetConnections() []*DeviceConnection {
	p.mu.RLock()
	defer p.mu.RUnlock()

	conns := make([]*DeviceConnection, 0, len(p.connections))
	for _, conn := range p.connections {
		conns = append(conns, conn)
	}
	return conns
}

// IsConnected checks if a device is connected
func (p *Proxy) IsConnected(device *models.Device) bool {
	adapter, ok := p.adapters[device.ManagementProtocol]
	if !ok {
		return false
	}
	return adapter.IsConnected(device)
}
