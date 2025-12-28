package attestation_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/attestation"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockRepository implements attestation.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) SaveReport(ctx context.Context, report *models.AttestationReport) error {
	args := m.Called(ctx, report)
	return args.Error(0)
}

func (m *MockRepository) GetReport(ctx context.Context, id uuid.UUID) (*models.AttestationReport, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AttestationReport), args.Error(1)
}

func (m *MockRepository) GetLatestReport(ctx context.Context, deviceID uuid.UUID) (*models.AttestationReport, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AttestationReport), args.Error(1)
}

func (m *MockRepository) ListReports(ctx context.Context, deviceID uuid.UUID, limit int) ([]*models.AttestationReport, error) {
	args := m.Called(ctx, deviceID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AttestationReport), args.Error(1)
}

func (m *MockRepository) SaveExpectedMeasurements(ctx context.Context, expected *models.ExpectedMeasurements) error {
	args := m.Called(ctx, expected)
	return args.Error(0)
}

func (m *MockRepository) GetExpectedMeasurements(ctx context.Context, deviceID uuid.UUID) (*models.ExpectedMeasurements, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ExpectedMeasurements), args.Error(1)
}

func (m *MockRepository) SaveVerificationResult(ctx context.Context, result *models.AttestationVerificationResult) error {
	args := m.Called(ctx, result)
	return args.Error(0)
}

// MockIdentityService implements attestation.IdentityService
type MockIdentityService struct {
	mock.Mock
}

func (m *MockIdentityService) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockIdentityService) UpdateTrustStatus(ctx context.Context, id uuid.UUID, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

// MockAuditLogger implements attestation.AuditLogger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogAttestationEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, result models.AuditResult, details map[string]interface{}) error {
	args := m.Called(ctx, eventType, deviceID, result, details)
	return args.Error(0)
}

// MockNotifier implements attestation.Notifier
type MockNotifier struct {
	mock.Mock
}

func (m *MockNotifier) SendAlert(ctx context.Context, alertType string, deviceID uuid.UUID, message string, severity string) error {
	args := m.Called(ctx, alertType, deviceID, message, severity)
	return args.Error(0)
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func createTestReport(deviceID uuid.UUID, nonce []byte) *models.AttestationReport {
	report := models.NewAttestationReport(deviceID, models.AttestationTypeSoftware, nonce)
	report.Measurements = models.DeviceMeasurements{
		FirmwareHash:      []byte("firmware-hash-abc123"),
		OSHash:            []byte("os-hash-def456"),
		RunningConfigHash: []byte("config-hash-ghi789"),
	}
	return report
}

func createTestExpected(deviceID uuid.UUID) *models.ExpectedMeasurements {
	return &models.ExpectedMeasurements{
		DeviceID:     deviceID,
		FirmwareHash: []byte("firmware-hash-abc123"),
		OSHash:       []byte("os-hash-def456"),
		UpdatedAt:    time.Now().UTC(),
		UpdatedBy:    uuid.New(),
	}
}

func TestNewVerifier(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	mockNotifier := new(MockNotifier)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry:         5 * time.Minute,
		PeriodicInterval:    time.Hour,
		RequireTPM:          false,
		QuarantineOnFailure: true,
		AlertOnFailure:      true,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, mockNotifier, logger, config)

	assert.NotNil(t, verifier)
}

func TestRequestAttestation(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()

	request, err := verifier.RequestAttestation(ctx, deviceID, true)

	assert.NoError(t, err)
	assert.NotNil(t, request)
	assert.Equal(t, deviceID, request.DeviceID)
	assert.NotEmpty(t, request.Nonce)
	assert.True(t, request.IncludeDetails)
}

func TestRequestAttestation_QuarantinedDevice(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()

	// Quarantine the device
	verifier.Quarantine(deviceID, "test quarantine")

	request, err := verifier.RequestAttestation(ctx, deviceID, true)

	assert.Error(t, err)
	assert.Equal(t, attestation.ErrDeviceQuarantined, err)
	assert.Nil(t, request)
}

func TestIsQuarantined(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()

	// Initially not quarantined
	assert.False(t, verifier.IsQuarantined(deviceID))

	// Quarantine
	verifier.Quarantine(deviceID, "test quarantine")
	assert.True(t, verifier.IsQuarantined(deviceID))

	// Unquarantine
	verifier.Unquarantine(deviceID)
	assert.False(t, verifier.IsQuarantined(deviceID))
}

func TestAttestationReport_SignAndVerify(t *testing.T) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)
	pubKey, privKey := generateKeyPair()

	// Sign
	report.Sign(privKey)
	assert.NotEmpty(t, report.SoftwareSignature)

	// Verify with correct key
	assert.True(t, report.VerifySoftwareSignature(pubKey))

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	assert.False(t, report.VerifySoftwareSignature(wrongPub))
}

func TestAttestationReport_Verify(t *testing.T) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)
	pubKey, privKey := generateKeyPair()
	report.Sign(privKey)

	expected := createTestExpected(deviceID)

	result := report.Verify(expected, pubKey)

	assert.NotNil(t, result)
	assert.Equal(t, deviceID, result.DeviceID)
	assert.Equal(t, report.ID, result.ReportID)
	assert.True(t, result.SignatureValid)
	assert.Equal(t, models.AttestationStatusVerified, result.Status)
}

func TestAttestationReport_Verify_SignatureFailure(t *testing.T) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)
	_, privKey := generateKeyPair()
	report.Sign(privKey)

	wrongPub, _ := generateKeyPair()
	expected := createTestExpected(deviceID)

	result := report.Verify(expected, wrongPub)

	assert.NotNil(t, result)
	assert.False(t, result.SignatureValid)
	assert.Equal(t, models.AttestationStatusFailed, result.Status)
}

func TestAttestationReport_Verify_MeasurementMismatch(t *testing.T) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)
	pubKey, privKey := generateKeyPair()
	report.Sign(privKey)

	expected := createTestExpected(deviceID)
	expected.FirmwareHash = []byte("different-firmware-hash")

	result := report.Verify(expected, pubKey)

	assert.NotNil(t, result)
	assert.True(t, result.SignatureValid)
	assert.False(t, result.MeasurementsValid)
	assert.Equal(t, models.AttestationStatusFailed, result.Status)
	assert.NotEmpty(t, result.Mismatches)
}

func TestDefaultAttestationPolicy(t *testing.T) {
	policy := models.DefaultAttestationPolicy()

	assert.NotNil(t, policy)
	assert.Equal(t, "default", policy.Name)
	assert.True(t, policy.AttestOnConnect)
	assert.True(t, policy.AttestOnConfigChange)
	assert.True(t, policy.VerifyFirmware)
	assert.True(t, policy.VerifyOS)
	assert.True(t, policy.VerifyConfig)
	assert.False(t, policy.RequireTPM)
	assert.True(t, policy.AlertOnFailure)
	assert.False(t, policy.QuarantineOnFailure)
}

func TestAttestationVerificationResult(t *testing.T) {
	result := &models.AttestationVerificationResult{
		DeviceID:          uuid.New(),
		ReportID:          uuid.New(),
		Status:            models.AttestationStatusVerified,
		VerifiedAt:        time.Now().UTC(),
		SignatureValid:    true,
		NonceValid:        true,
		MeasurementsValid: true,
	}

	assert.Equal(t, models.AttestationStatusVerified, result.Status)
	assert.True(t, result.SignatureValid)
	assert.True(t, result.NonceValid)
	assert.True(t, result.MeasurementsValid)
}

func TestNewAttestationReport(t *testing.T) {
	deviceID := uuid.New()
	nonce := []byte("test-nonce")

	report := models.NewAttestationReport(deviceID, models.AttestationTypeSoftware, nonce)

	assert.NotNil(t, report)
	assert.NotEqual(t, uuid.Nil, report.ID)
	assert.Equal(t, deviceID, report.DeviceID)
	assert.Equal(t, models.AttestationTypeSoftware, report.Type)
	assert.Equal(t, nonce, report.Nonce)
	assert.False(t, report.Timestamp.IsZero())
}

func TestAttestationReport_Hash(t *testing.T) {
	deviceID := uuid.New()
	nonce := []byte("test-nonce")

	report := models.NewAttestationReport(deviceID, models.AttestationTypeSoftware, nonce)
	report.Measurements.FirmwareHash = []byte("firmware")
	report.Measurements.OSHash = []byte("os")

	hash1 := report.Hash()
	hash2 := report.Hash()

	// Hash should be deterministic
	assert.Equal(t, hash1, hash2)

	// Changing measurements should change hash
	report.Measurements.FirmwareHash = []byte("different-firmware")
	hash3 := report.Hash()
	assert.NotEqual(t, hash1, hash3)
}

// Benchmark tests
func BenchmarkAttestationSign(b *testing.B) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	_, privKey := generateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := createTestReport(deviceID, nonce)
		report.Sign(privKey)
	}
}

func BenchmarkAttestationVerify(b *testing.B) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	pubKey, privKey := generateKeyPair()
	report := createTestReport(deviceID, nonce)
	report.Sign(privKey)
	expected := createTestExpected(deviceID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.Verify(expected, pubKey)
	}
}

func BenchmarkReportHash(b *testing.B) {
	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	report := createTestReport(deviceID, nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.Hash()
	}
}

func TestNewVerifier_WithNilConfig(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	assert.NotNil(t, verifier)
	policy := verifier.GetPolicy()
	assert.NotNil(t, policy)
	assert.False(t, policy.RequireTPM) // Default
}

func TestVerifier_GetQuarantinedDevices(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	// Initially empty
	devices := verifier.GetQuarantinedDevices()
	assert.Empty(t, devices)

	// Add some devices
	device1 := uuid.New()
	device2 := uuid.New()
	verifier.Quarantine(device1, "reason1")
	verifier.Quarantine(device2, "reason2")

	devices = verifier.GetQuarantinedDevices()
	assert.Len(t, devices, 2)
	assert.Contains(t, devices, device1)
	assert.Contains(t, devices, device2)
}

func TestVerifier_GetLatestReport(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	expectedReport := createTestReport(deviceID, []byte("nonce"))

	mockRepo.On("GetLatestReport", ctx, deviceID).Return(expectedReport, nil)

	report, err := verifier.GetLatestReport(ctx, deviceID)

	assert.NoError(t, err)
	assert.Equal(t, expectedReport, report)
	mockRepo.AssertExpectations(t)
}

func TestVerifier_ListReports(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	reports := []*models.AttestationReport{
		createTestReport(deviceID, []byte("nonce1")),
		createTestReport(deviceID, []byte("nonce2")),
	}

	mockRepo.On("ListReports", ctx, deviceID, 50).Return(reports, nil)

	result, err := verifier.ListReports(ctx, deviceID, 0) // 0 should default to 50

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	mockRepo.AssertExpectations(t)
}

func TestVerifier_ListReports_WithLimit(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	reports := []*models.AttestationReport{
		createTestReport(deviceID, []byte("nonce1")),
	}

	mockRepo.On("ListReports", ctx, deviceID, 10).Return(reports, nil)

	result, err := verifier.ListReports(ctx, deviceID, 10)

	assert.NoError(t, err)
	assert.Len(t, result, 1)
	mockRepo.AssertExpectations(t)
}

func TestVerifier_UpdateExpectedMeasurements(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	updatedBy := uuid.New()
	expected := createTestExpected(deviceID)

	mockRepo.On("SaveExpectedMeasurements", ctx, mock.Anything).Return(nil)

	err := verifier.UpdateExpectedMeasurements(ctx, expected, updatedBy)

	assert.NoError(t, err)
	assert.Equal(t, updatedBy, expected.UpdatedBy)
	mockRepo.AssertExpectations(t)
}

func TestVerifier_GetPolicy(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		RequireTPM:          true,
		QuarantineOnFailure: true,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	policy := verifier.GetPolicy()

	assert.NotNil(t, policy)
	assert.True(t, policy.RequireTPM)
	assert.True(t, policy.QuarantineOnFailure)
}

func TestVerifier_UpdatePolicy(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	newPolicy := &models.AttestationPolicy{
		Name:                "custom-policy",
		RequireTPM:          true,
		AlertOnFailure:      true,
		QuarantineOnFailure: true,
	}

	verifier.UpdatePolicy(newPolicy)

	policy := verifier.GetPolicy()
	assert.Equal(t, "custom-policy", policy.Name)
	assert.True(t, policy.RequireTPM)
	assert.False(t, policy.UpdatedAt.IsZero())
}

func TestRequestAttestation_WithTPMRequired(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
		RequireTPM:  true,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()

	request, err := verifier.RequestAttestation(ctx, deviceID, false)

	assert.NoError(t, err)
	assert.NotNil(t, request)
	assert.NotEmpty(t, request.RequestedPCRs)
	assert.False(t, request.IncludeDetails)
}

func TestVerifier_VerifyTPMSignature(t *testing.T) {
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)
	pubKey, _ := generateKeyPair()

	// No TPM signature - should fail
	assert.False(t, verifier.VerifyTPMSignature(report, pubKey))

	// With TPM signature and AIK cert
	report.TPMSignature = []byte("tpm-signature")
	report.AIKCert = []byte("aik-cert")
	assert.True(t, verifier.VerifyTPMSignature(report, pubKey))
}

func TestGenerateDeviceMeasurements(t *testing.T) {
	firmware := []byte("firmware-data")
	os := []byte("os-data")
	agent := []byte("agent-data")
	runningConfig := "running-config"
	startupConfig := "startup-config"

	measurements := attestation.GenerateDeviceMeasurements(firmware, os, agent, runningConfig, startupConfig)

	assert.NotNil(t, measurements)
	assert.NotEmpty(t, measurements.FirmwareHash)
	assert.NotEmpty(t, measurements.OSHash)
	assert.NotEmpty(t, measurements.AgentHash)
	assert.NotEmpty(t, measurements.RunningConfigHash)
	assert.NotEmpty(t, measurements.StartupConfigHash)

	// Hashes should be SHA256 (32 bytes)
	assert.Len(t, measurements.FirmwareHash, 32)
	assert.Len(t, measurements.OSHash, 32)
	assert.Len(t, measurements.AgentHash, 32)
}

func TestExpectedMeasurements(t *testing.T) {
	deviceID := uuid.New()
	updatedBy := uuid.New()

	expected := &models.ExpectedMeasurements{
		DeviceID:         deviceID,
		FirmwareHash:     []byte("firmware-hash"),
		OSHash:           []byte("os-hash"),
		AgentHash:        []byte("agent-hash"),
		AllowedProcesses: []string{"agent", "sshd"},
		ExpectedPorts: []models.PortInfo{
			{Port: 22, Protocol: "tcp"},
			{Port: 443, Protocol: "tcp"},
		},
		UpdatedAt: time.Now(),
		UpdatedBy: updatedBy,
	}

	assert.Equal(t, deviceID, expected.DeviceID)
	assert.Len(t, expected.AllowedProcesses, 2)
	assert.Len(t, expected.ExpectedPorts, 2)
}

func TestAttestationTypes(t *testing.T) {
	assert.Equal(t, models.AttestationType("software"), models.AttestationTypeSoftware)
	assert.Equal(t, models.AttestationType("tpm"), models.AttestationTypeTPM)
	assert.Equal(t, models.AttestationType("remote"), models.AttestationTypeRemote)
}

func TestAttestationStatus(t *testing.T) {
	assert.Equal(t, models.AttestationStatus("pending"), models.AttestationStatusPending)
	assert.Equal(t, models.AttestationStatus("verified"), models.AttestationStatusVerified)
	assert.Equal(t, models.AttestationStatus("failed"), models.AttestationStatusFailed)
	assert.Equal(t, models.AttestationStatus("expired"), models.AttestationStatusExpired)
}

func TestAttestationErrors(t *testing.T) {
	assert.Error(t, attestation.ErrDeviceNotFound)
	assert.Error(t, attestation.ErrAttestationFailed)
	assert.Error(t, attestation.ErrInvalidNonce)
	assert.Error(t, attestation.ErrDeviceQuarantined)
	assert.Error(t, attestation.ErrMissingExpectedMeasurements)
}

func TestVerifyAttestation_InvalidNonce(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, nil)

	deviceID := uuid.New()
	nonce := make([]byte, 32)
	rand.Read(nonce)

	report := createTestReport(deviceID, nonce)

	// Nonce was never registered, should fail
	result, err := verifier.VerifyAttestation(ctx, report)

	assert.Error(t, err)
	assert.Equal(t, attestation.ErrInvalidNonce, err)
	assert.Nil(t, result)
}

func TestVerifyAttestation_Success(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()
	pubKey, privKey := generateKeyPair()

	// Request attestation to get a valid nonce
	request, err := verifier.RequestAttestation(ctx, deviceID, true)
	assert.NoError(t, err)

	// Create a report with the valid nonce
	report := createTestReport(deviceID, request.Nonce)
	report.Sign(privKey)

	// Set up mocks
	identity := &models.Identity{
		ID:        deviceID,
		PublicKey: pubKey,
	}
	expected := createTestExpected(deviceID)

	mockIdentity.On("GetByID", ctx, deviceID).Return(identity, nil)
	mockRepo.On("GetExpectedMeasurements", ctx, deviceID).Return(expected, nil)
	mockRepo.On("SaveReport", ctx, mock.Anything).Return(nil)
	mockRepo.On("SaveVerificationResult", ctx, mock.Anything).Return(nil)
	mockIdentity.On("UpdateTrustStatus", ctx, deviceID, "verified").Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, mock.Anything, deviceID, mock.Anything, mock.Anything).Return(nil)

	result, err := verifier.VerifyAttestation(ctx, report)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.AttestationStatusVerified, result.Status)
	assert.True(t, result.SignatureValid)
	mockRepo.AssertExpectations(t)
	mockIdentity.AssertExpectations(t)
}

func TestVerifyAttestation_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()
	_, privKey := generateKeyPair()

	// Request attestation to get a valid nonce
	request, _ := verifier.RequestAttestation(ctx, deviceID, false)

	// Create a report
	report := createTestReport(deviceID, request.Nonce)
	report.Sign(privKey)

	// Device not found
	mockIdentity.On("GetByID", ctx, deviceID).Return(nil, errors.New("not found"))

	result, err := verifier.VerifyAttestation(ctx, report)

	assert.Error(t, err)
	assert.Equal(t, attestation.ErrDeviceNotFound, err)
	assert.Nil(t, result)
}

func TestVerifyAttestation_FirstAttestation_SavesBaseline(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry: 5 * time.Minute,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, nil, logger, config)

	deviceID := uuid.New()
	pubKey, privKey := generateKeyPair()

	// Request attestation
	request, _ := verifier.RequestAttestation(ctx, deviceID, false)

	// Create a report
	report := createTestReport(deviceID, request.Nonce)
	report.Sign(privKey)

	identity := &models.Identity{
		ID:        deviceID,
		PublicKey: pubKey,
	}

	// No existing measurements - this is first attestation
	mockIdentity.On("GetByID", ctx, deviceID).Return(identity, nil)
	mockRepo.On("GetExpectedMeasurements", ctx, deviceID).Return(nil, errors.New("not found"))
	mockRepo.On("SaveExpectedMeasurements", ctx, mock.Anything).Return(nil)
	mockRepo.On("SaveReport", ctx, mock.Anything).Return(nil)
	mockRepo.On("SaveVerificationResult", ctx, mock.Anything).Return(nil)
	mockIdentity.On("UpdateTrustStatus", ctx, deviceID, "verified").Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, mock.Anything, deviceID, mock.Anything, mock.Anything).Return(nil)

	result, err := verifier.VerifyAttestation(ctx, report)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	mockRepo.AssertCalled(t, "SaveExpectedMeasurements", ctx, mock.Anything)
}

func TestVerifyAttestation_FailedWithQuarantine(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)
	mockNotifier := new(MockNotifier)
	logger := zap.NewNop()

	config := &attestation.Config{
		NonceExpiry:         5 * time.Minute,
		QuarantineOnFailure: true,
		AlertOnFailure:      true,
	}

	verifier := attestation.NewVerifier(mockRepo, mockIdentity, mockAudit, mockNotifier, logger, config)

	deviceID := uuid.New()
	pubKey, privKey := generateKeyPair()

	// Request attestation
	request, _ := verifier.RequestAttestation(ctx, deviceID, false)

	// Create a report
	report := createTestReport(deviceID, request.Nonce)
	report.Sign(privKey)

	identity := &models.Identity{
		ID:        deviceID,
		PublicKey: pubKey,
	}

	// Expected measurements differ
	expected := createTestExpected(deviceID)
	expected.FirmwareHash = []byte("different-firmware-hash")

	mockIdentity.On("GetByID", ctx, deviceID).Return(identity, nil)
	mockRepo.On("GetExpectedMeasurements", ctx, deviceID).Return(expected, nil)
	mockRepo.On("SaveReport", ctx, mock.Anything).Return(nil)
	mockRepo.On("SaveVerificationResult", ctx, mock.Anything).Return(nil)
	mockIdentity.On("UpdateTrustStatus", ctx, deviceID, "untrusted").Return(nil)
	mockNotifier.On("SendAlert", ctx, "attestation_failure", deviceID, mock.Anything, "critical").Return(nil)
	mockAudit.On("LogAttestationEvent", ctx, mock.Anything, deviceID, mock.Anything, mock.Anything).Return(nil)

	result, err := verifier.VerifyAttestation(ctx, report)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.AttestationStatusFailed, result.Status)
	assert.True(t, verifier.IsQuarantined(deviceID))
	mockNotifier.AssertCalled(t, "SendAlert", ctx, "attestation_failure", deviceID, mock.Anything, "critical")
}
