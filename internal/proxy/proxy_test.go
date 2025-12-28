package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockProtocolAdapter is a mock implementation of ProtocolAdapter
type MockProtocolAdapter struct {
	mock.Mock
}

func (m *MockProtocolAdapter) Connect(ctx context.Context, device *models.Device, credentials []byte) error {
	args := m.Called(ctx, device, credentials)
	return args.Error(0)
}

func (m *MockProtocolAdapter) Disconnect(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockProtocolAdapter) Execute(ctx context.Context, device *models.Device, command string) (*ExecutionResult, error) {
	args := m.Called(ctx, device, command)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ExecutionResult), args.Error(1)
}

func (m *MockProtocolAdapter) GetConfig(ctx context.Context, device *models.Device, section string) (string, error) {
	args := m.Called(ctx, device, section)
	return args.String(0), args.Error(1)
}

func (m *MockProtocolAdapter) SetConfig(ctx context.Context, device *models.Device, commands []string) error {
	args := m.Called(ctx, device, commands)
	return args.Error(0)
}

func (m *MockProtocolAdapter) IsConnected(device *models.Device) bool {
	args := m.Called(device)
	return args.Bool(0)
}

// MockSessionRecorder is a mock implementation of SessionRecorder
type MockSessionRecorder struct {
	mock.Mock
}

func (m *MockSessionRecorder) StartSession(deviceID, operatorID uuid.UUID) (uuid.UUID, error) {
	args := m.Called(deviceID, operatorID)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockSessionRecorder) RecordCommand(sessionID uuid.UUID, command string, output string, duration time.Duration) error {
	args := m.Called(sessionID, command, output, duration)
	return args.Error(0)
}

func (m *MockSessionRecorder) EndSession(sessionID uuid.UUID) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

// MockRateLimiter is a mock implementation of RateLimiter
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(key string, limit int, period time.Duration) bool {
	args := m.Called(key, limit, period)
	return args.Bool(0)
}

func TestCredentials(t *testing.T) {
	creds := Credentials{
		Username:   "admin",
		Password:   "secret",
		PrivateKey: []byte("ssh-key"),
		APIKey:     "api-key",
		Token:      "token",
	}

	assert.Equal(t, "admin", creds.Username)
	assert.Equal(t, "secret", creds.Password)
	assert.Equal(t, []byte("ssh-key"), creds.PrivateKey)
	assert.Equal(t, "api-key", creds.APIKey)
	assert.Equal(t, "token", creds.Token)
}

func TestOperation(t *testing.T) {
	op := &Operation{
		Action:       "get-config",
		ResourcePath: "/running-config",
		Parameters: map[string]interface{}{
			"format": "json",
		},
		Data: map[string]string{"key": "value"},
	}

	assert.Equal(t, "get-config", op.Action)
	assert.Equal(t, "/running-config", op.ResourcePath)
	assert.Equal(t, "json", op.Parameters["format"])
	assert.NotNil(t, op.Data)
}

func TestOperationResult(t *testing.T) {
	result := &OperationResult{
		Success:    true,
		Output:     "config output",
		Data:       map[string]interface{}{"hostname": "router1"},
		Error:      "",
		Duration:   150 * time.Millisecond,
		StatusCode: 200,
	}

	assert.True(t, result.Success)
	assert.Equal(t, "config output", result.Output)
	assert.Equal(t, 150*time.Millisecond, result.Duration)
	assert.Equal(t, 200, result.StatusCode)
	assert.Empty(t, result.Error)
}

func TestOperationResult_Error(t *testing.T) {
	result := &OperationResult{
		Success:    false,
		Output:     "",
		Error:      "connection refused",
		Duration:   50 * time.Millisecond,
		StatusCode: 0,
	}

	assert.False(t, result.Success)
	assert.Equal(t, "connection refused", result.Error)
}

// ========== Proxy Tests ==========

func TestNewProxy(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.adapters)
	assert.NotNil(t, proxy.connections)
	assert.NotNil(t, proxy.commandFilter)
}

func TestProxy_RegisterAdapter(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)

	assert.Len(t, proxy.adapters, 1)
	assert.Equal(t, mockAdapter, proxy.adapters[models.ProtocolTypeSSH])
}

func TestProxy_SetSessionRecorder(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockRecorder := new(MockSessionRecorder)

	proxy.SetSessionRecorder(mockRecorder)

	assert.Equal(t, mockRecorder, proxy.sessionRecorder)
}

func TestProxy_SetRateLimiter(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockLimiter := new(MockRateLimiter)

	proxy.SetRateLimiter(mockLimiter)

	assert.Equal(t, mockLimiter, proxy.rateLimiter)
}

func TestProxy_SetCommandFilter(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	filter := &models.CommandFilter{
		BlockedAlways: []string{"rm -rf"},
	}

	proxy.SetCommandFilter(filter)

	assert.Equal(t, filter, proxy.commandFilter)
}

func TestProxy_Connect_Success(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}

	mockAdapter.On("Connect", mock.Anything, device, []byte("creds")).Return(nil)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)

	err := proxy.Connect(context.Background(), device, []byte("creds"), nil)

	assert.NoError(t, err)
	mockAdapter.AssertExpectations(t)

	// Check connection is tracked
	conns := proxy.GetConnections()
	assert.Len(t, conns, 1)
	assert.Equal(t, device.ID, conns[0].DeviceID)
}

func TestProxy_Connect_WithSessionRecorder(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)
	mockRecorder := new(MockSessionRecorder)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}
	operatorID := uuid.New()
	sessionID := uuid.New()

	mockAdapter.On("Connect", mock.Anything, device, []byte("creds")).Return(nil)
	mockRecorder.On("StartSession", device.ID, operatorID).Return(sessionID, nil)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)
	proxy.SetSessionRecorder(mockRecorder)

	err := proxy.Connect(context.Background(), device, []byte("creds"), &operatorID)

	assert.NoError(t, err)
	mockAdapter.AssertExpectations(t)
	mockRecorder.AssertExpectations(t)

	// Check session is tracked
	conn := proxy.getConnection(device.ID)
	assert.NotNil(t, conn)
	assert.Equal(t, sessionID, conn.SessionID)
}

func TestProxy_Connect_UnsupportedProtocol(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH, // No adapter registered
	}

	err := proxy.Connect(context.Background(), device, []byte("creds"), nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
}

func TestProxy_Disconnect_Success(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}

	mockAdapter.On("Connect", mock.Anything, device, []byte("creds")).Return(nil)
	mockAdapter.On("Disconnect", mock.Anything, device).Return(nil)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)

	// Connect first
	err := proxy.Connect(context.Background(), device, []byte("creds"), nil)
	assert.NoError(t, err)
	assert.Len(t, proxy.GetConnections(), 1)

	// Disconnect
	err = proxy.Disconnect(context.Background(), device)
	assert.NoError(t, err)
	assert.Len(t, proxy.GetConnections(), 0)

	mockAdapter.AssertExpectations(t)
}

func TestProxy_Disconnect_WithSessionRecorder(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)
	mockRecorder := new(MockSessionRecorder)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}
	operatorID := uuid.New()
	sessionID := uuid.New()

	mockAdapter.On("Connect", mock.Anything, device, []byte("creds")).Return(nil)
	mockAdapter.On("Disconnect", mock.Anything, device).Return(nil)
	mockRecorder.On("StartSession", device.ID, operatorID).Return(sessionID, nil)
	mockRecorder.On("EndSession", sessionID).Return(nil)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)
	proxy.SetSessionRecorder(mockRecorder)

	// Connect
	err := proxy.Connect(context.Background(), device, []byte("creds"), &operatorID)
	assert.NoError(t, err)

	// Disconnect
	err = proxy.Disconnect(context.Background(), device)
	assert.NoError(t, err)

	mockRecorder.AssertExpectations(t)
}

func TestProxy_IsConnected(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	mockAdapter := new(MockProtocolAdapter)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}

	mockAdapter.On("IsConnected", device).Return(true)

	proxy.RegisterAdapter(models.ProtocolTypeSSH, mockAdapter)

	result := proxy.IsConnected(device)

	assert.True(t, result)
	mockAdapter.AssertExpectations(t)
}

func TestProxy_IsConnected_NoAdapter(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	device := &models.Device{
		ID:                 uuid.New(),
		ManagementProtocol: models.ProtocolTypeSSH,
	}

	result := proxy.IsConnected(device)

	assert.False(t, result)
}

func TestProxy_GetConnections_Empty(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	conns := proxy.GetConnections()

	assert.Empty(t, conns)
}

func TestProxy_isBlocked(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	proxy.commandFilter = &models.CommandFilter{
		BlockedAlways: []string{
			"rm -rf",
			"format*",
			"delete",
		},
	}

	tests := []struct {
		command string
		blocked bool
	}{
		{"rm -rf", true},
		{"RM -RF", true}, // Case insensitive
		{"format disk", true},
		{"format c:", true},
		{"delete", true},
		{"show running-config", false},
		{"ping 8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			result := proxy.isBlocked(tt.command)
			assert.Equal(t, tt.blocked, result)
		})
	}
}

func TestProxy_requiresConfirmation(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	proxy.commandFilter = &models.CommandFilter{
		RequireConfirmation: []string{
			"reload",
			"write erase*",
		},
	}

	tests := []struct {
		command  string
		requires bool
	}{
		{"reload", true},
		{"RELOAD", true}, // Case insensitive
		{"write erase", true},
		{"write erase all", true},
		{"show running-config", false},
		{"write memory", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			result := proxy.requiresConfirmation(tt.command)
			assert.Equal(t, tt.requires, result)
		})
	}
}

func TestProxy_sanitizeOutput(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)
	proxy.commandFilter = &models.CommandFilter{
		SanitizePatterns: []models.SanitizePattern{
			{Pattern: `password\s+\S+`, Replace: "password ****"},
			{Pattern: `secret\s+\S+`, Replace: "secret ****"},
		},
	}

	input := "hostname router1\npassword mySecretPass123\nenable secret anotherSecret"
	expected := "hostname router1\npassword ****\nenable secret ****"

	result := proxy.sanitizeOutput(input)

	assert.Equal(t, expected, result)
}

func TestProxy_operationTypeToAction(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	tests := []struct {
		opType   models.OperationType
		expected models.ActionType
	}{
		{models.OperationTypeRead, models.ActionConfigRead},
		{models.OperationTypeWrite, models.ActionConfigWrite},
		{models.OperationTypeExec, models.ActionExecCommand},
		{models.OperationType(99), models.ActionConfigRead}, // Default for unknown
	}

	for _, tt := range tests {
		result := proxy.operationTypeToAction(tt.opType)
		assert.Equal(t, tt.expected, result)
	}
}

func TestProxy_failedResult(t *testing.T) {
	logger := zap.NewNop()
	proxy := NewProxy(nil, logger)

	requestID := uuid.New()
	deviceID := uuid.New()
	startTime := time.Now().UnixMilli()

	result, err := proxy.failedResult(requestID, deviceID, startTime, "test error")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, requestID, result.RequestID)
	assert.Equal(t, deviceID, result.DeviceID)
	assert.Equal(t, models.OperationResultFailure, result.Status)
	assert.Equal(t, "test error", result.Error)
	assert.Equal(t, startTime, result.StartTime)
	assert.True(t, result.DurationMs >= 0)
}

func TestDeviceConnection(t *testing.T) {
	operatorID := uuid.New()
	conn := &DeviceConnection{
		DeviceID:       uuid.New(),
		Protocol:       models.ProtocolTypeSSH,
		ConnectedAt:    time.Now(),
		LastActivityAt: time.Now(),
		SessionID:      uuid.New(),
		OperatorID:     &operatorID,
	}

	assert.NotEqual(t, uuid.Nil, conn.DeviceID)
	assert.Equal(t, models.ProtocolTypeSSH, conn.Protocol)
	assert.NotNil(t, conn.OperatorID)
}

func TestExecutionResult(t *testing.T) {
	result := &ExecutionResult{
		Output:    "command output",
		Error:     "",
		Duration:  100 * time.Millisecond,
		ExitCode:  0,
		Truncated: false,
	}

	assert.Equal(t, "command output", result.Output)
	assert.Empty(t, result.Error)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
	assert.Equal(t, 0, result.ExitCode)
	assert.False(t, result.Truncated)
}

func TestExecutionResult_WithError(t *testing.T) {
	result := &ExecutionResult{
		Output:    "",
		Error:     "command failed",
		Duration:  50 * time.Millisecond,
		ExitCode:  1,
		Truncated: false,
	}

	assert.Empty(t, result.Output)
	assert.Equal(t, "command failed", result.Error)
	assert.Equal(t, 1, result.ExitCode)
}
