package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

var (
	ErrDeviceNotFound          = errors.New("device not found")
	ErrAttestationFailed       = errors.New("attestation verification failed")
	ErrInvalidNonce            = errors.New("invalid or expired nonce")
	ErrDeviceQuarantined       = errors.New("device is quarantined")
	ErrMissingExpectedMeasurements = errors.New("missing expected measurements for device")
)

// Repository interface for attestation persistence
type Repository interface {
	SaveReport(ctx context.Context, report *models.AttestationReport) error
	GetReport(ctx context.Context, id uuid.UUID) (*models.AttestationReport, error)
	GetLatestReport(ctx context.Context, deviceID uuid.UUID) (*models.AttestationReport, error)
	ListReports(ctx context.Context, deviceID uuid.UUID, limit int) ([]*models.AttestationReport, error)
	SaveExpectedMeasurements(ctx context.Context, expected *models.ExpectedMeasurements) error
	GetExpectedMeasurements(ctx context.Context, deviceID uuid.UUID) (*models.ExpectedMeasurements, error)
	SaveVerificationResult(ctx context.Context, result *models.AttestationVerificationResult) error
}

// IdentityService interface for device identity operations
type IdentityService interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error)
	UpdateTrustStatus(ctx context.Context, id uuid.UUID, status string) error
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogAttestationEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, result models.AuditResult, details map[string]interface{}) error
}

// Notifier interface for alerts
type Notifier interface {
	SendAlert(ctx context.Context, alertType string, deviceID uuid.UUID, message string, severity string) error
}

// Verifier handles device attestation verification
type Verifier struct {
	repo            Repository
	identitySvc     IdentityService
	auditLog        AuditLogger
	notifier        Notifier
	logger          *zap.Logger
	policy          *models.AttestationPolicy

	// Nonce management
	nonceStore      map[string]nonceEntry
	nonceMu         sync.RWMutex
	nonceExpiry     time.Duration

	// Quarantine management
	quarantinedDevices map[uuid.UUID]time.Time
	quarantineMu       sync.RWMutex
}

type nonceEntry struct {
	deviceID  uuid.UUID
	createdAt time.Time
	used      bool
}

// Config contains verifier configuration
type Config struct {
	NonceExpiry         time.Duration
	PeriodicInterval    time.Duration
	RequireTPM          bool
	QuarantineOnFailure bool
	AlertOnFailure      bool
}

// NewVerifier creates a new attestation verifier
func NewVerifier(
	repo Repository,
	identitySvc IdentityService,
	auditLog AuditLogger,
	notifier Notifier,
	logger *zap.Logger,
	config *Config,
) *Verifier {
	policy := models.DefaultAttestationPolicy()
	if config != nil {
		policy.RequireTPM = config.RequireTPM
		policy.QuarantineOnFailure = config.QuarantineOnFailure
		policy.AlertOnFailure = config.AlertOnFailure
		if config.PeriodicInterval > 0 {
			policy.PeriodicIntervalMinutes = int(config.PeriodicInterval.Minutes())
		}
	}

	nonceExpiry := 5 * time.Minute
	if config != nil && config.NonceExpiry > 0 {
		nonceExpiry = config.NonceExpiry
	}

	v := &Verifier{
		repo:               repo,
		identitySvc:        identitySvc,
		auditLog:           auditLog,
		notifier:           notifier,
		logger:             logger,
		policy:             policy,
		nonceStore:         make(map[string]nonceEntry),
		nonceExpiry:        nonceExpiry,
		quarantinedDevices: make(map[uuid.UUID]time.Time),
	}

	// Start nonce cleanup goroutine
	go v.cleanupExpiredNonces()

	return v
}

// RequestAttestation creates a new attestation request for a device
func (v *Verifier) RequestAttestation(ctx context.Context, deviceID uuid.UUID, includeDetails bool) (*models.AttestationRequest, error) {
	// Check if device is quarantined
	if v.IsQuarantined(deviceID) {
		return nil, ErrDeviceQuarantined
	}

	// Generate nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	nonceHex := hex.EncodeToString(nonce)

	// Store nonce
	v.nonceMu.Lock()
	v.nonceStore[nonceHex] = nonceEntry{
		deviceID:  deviceID,
		createdAt: time.Now(),
		used:      false,
	}
	v.nonceMu.Unlock()

	request := &models.AttestationRequest{
		DeviceID:       deviceID,
		Nonce:          nonce,
		IncludeDetails: includeDetails,
		Timeout:        60,
	}

	// Add required PCRs if TPM is required
	if v.policy.RequireTPM {
		request.RequestedPCRs = v.policy.RequiredPCRs
		if len(request.RequestedPCRs) == 0 {
			request.RequestedPCRs = []int{0, 1, 2, 7} // Default PCRs
		}
	}

	v.logger.Info("Attestation requested",
		zap.String("device_id", deviceID.String()),
		zap.Bool("include_details", includeDetails),
	)

	return request, nil
}

// VerifyAttestation verifies an attestation report from a device
func (v *Verifier) VerifyAttestation(ctx context.Context, report *models.AttestationReport) (*models.AttestationVerificationResult, error) {
	startTime := time.Now()

	// Validate nonce
	nonceHex := hex.EncodeToString(report.Nonce)
	v.nonceMu.Lock()
	entry, exists := v.nonceStore[nonceHex]
	if !exists {
		v.nonceMu.Unlock()
		return nil, ErrInvalidNonce
	}
	if entry.used {
		v.nonceMu.Unlock()
		return nil, ErrInvalidNonce
	}
	if time.Since(entry.createdAt) > v.nonceExpiry {
		delete(v.nonceStore, nonceHex)
		v.nonceMu.Unlock()
		return nil, ErrInvalidNonce
	}
	if entry.deviceID != report.DeviceID {
		v.nonceMu.Unlock()
		return nil, ErrInvalidNonce
	}
	entry.used = true
	v.nonceStore[nonceHex] = entry
	v.nonceMu.Unlock()

	// Get device identity
	identity, err := v.identitySvc.GetByID(ctx, report.DeviceID)
	if err != nil {
		return nil, ErrDeviceNotFound
	}

	// Get expected measurements
	expected, err := v.repo.GetExpectedMeasurements(ctx, report.DeviceID)
	if err != nil {
		v.logger.Warn("No expected measurements found, using report as baseline",
			zap.String("device_id", report.DeviceID.String()),
		)
		// First attestation - save as baseline
		expected = &models.ExpectedMeasurements{
			DeviceID:     report.DeviceID,
			FirmwareHash: report.Measurements.FirmwareHash,
			OSHash:       report.Measurements.OSHash,
			AgentHash:    report.Measurements.AgentHash,
			UpdatedAt:    time.Now(),
		}
		if err := v.repo.SaveExpectedMeasurements(ctx, expected); err != nil {
			v.logger.Error("Failed to save baseline measurements", zap.Error(err))
		}
	}

	// Verify the report
	result := report.Verify(expected, identity.PublicKey)

	// Additional verifications based on policy
	v.performPolicyChecks(report, expected, result)

	// Save the report
	if err := v.repo.SaveReport(ctx, report); err != nil {
		v.logger.Error("Failed to save attestation report", zap.Error(err))
	}

	// Save verification result
	if err := v.repo.SaveVerificationResult(ctx, result); err != nil {
		v.logger.Error("Failed to save verification result", zap.Error(err))
	}

	// Handle result based on policy
	if err := v.handleVerificationResult(ctx, result); err != nil {
		v.logger.Error("Failed to handle verification result", zap.Error(err))
	}

	// Log to audit
	if v.auditLog != nil {
		eventType := models.AuditEventDeviceAttest
		auditResult := models.AuditResultSuccess
		if result.Status == models.AttestationStatusFailed {
			eventType = models.AuditEventDeviceAttestFail
			auditResult = models.AuditResultFailure
		}
		v.auditLog.LogAttestationEvent(ctx, eventType, report.DeviceID, auditResult, map[string]interface{}{
			"report_id":          result.ReportID,
			"status":             result.Status,
			"signature_valid":    result.SignatureValid,
			"measurements_valid": result.MeasurementsValid,
			"mismatches":         len(result.Mismatches),
			"duration_ms":        time.Since(startTime).Milliseconds(),
		})
	}

	v.logger.Info("Attestation verification completed",
		zap.String("device_id", report.DeviceID.String()),
		zap.String("status", string(result.Status)),
		zap.Int("mismatches", len(result.Mismatches)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// performPolicyChecks performs additional checks based on attestation policy
func (v *Verifier) performPolicyChecks(report *models.AttestationReport, expected *models.ExpectedMeasurements, result *models.AttestationVerificationResult) {
	// Check TPM requirement
	if v.policy.RequireTPM && report.Type != models.AttestationTypeTPM {
		result.Warnings = append(result.Warnings, "TPM attestation required but software attestation received")
	}

	// Check process list if enabled
	if v.policy.VerifyProcesses && expected != nil && len(expected.AllowedProcesses) > 0 {
		for _, proc := range report.Measurements.ActiveProcesses {
			allowed := false
			for _, allowedProc := range expected.AllowedProcesses {
				if proc.Name == allowedProc {
					allowed = true
					break
				}
			}
			if !allowed {
				result.Warnings = append(result.Warnings, "Unexpected process: "+proc.Name)
			}
		}
	}

	// Check open ports if enabled
	if v.policy.VerifyPorts && expected != nil && len(expected.ExpectedPorts) > 0 {
		for _, port := range report.Measurements.OpenPorts {
			found := false
			for _, expectedPort := range expected.ExpectedPorts {
				if port.Port == expectedPort.Port && port.Protocol == expectedPort.Protocol {
					found = true
					break
				}
			}
			if !found {
				result.Warnings = append(result.Warnings, "Unexpected open port: "+string(rune(port.Port)))
			}
		}
	}

	// Check config hash consistency
	if v.policy.VerifyConfig {
		if len(report.Measurements.RunningConfigHash) > 0 && len(report.Measurements.StartupConfigHash) > 0 {
			if !bytesEqual(report.Measurements.RunningConfigHash, report.Measurements.StartupConfigHash) {
				result.Warnings = append(result.Warnings, "Running config differs from startup config")
			}
		}
	}
}

// handleVerificationResult handles the verification result based on policy
func (v *Verifier) handleVerificationResult(ctx context.Context, result *models.AttestationVerificationResult) error {
	if result.Status == models.AttestationStatusFailed {
		// Update device trust status
		if err := v.identitySvc.UpdateTrustStatus(ctx, result.DeviceID, "untrusted"); err != nil {
			v.logger.Error("Failed to update device trust status", zap.Error(err))
		}

		// Quarantine if policy requires
		if v.policy.QuarantineOnFailure {
			v.Quarantine(result.DeviceID, "attestation_failed")
		}

		// Send alert if configured
		if v.policy.AlertOnFailure && v.notifier != nil {
			message := "Device attestation failed"
			if len(result.Mismatches) > 0 {
				message += ": " + result.Mismatches[0].Message
			}
			if err := v.notifier.SendAlert(ctx, "attestation_failure", result.DeviceID, message, "critical"); err != nil {
				v.logger.Error("Failed to send alert", zap.Error(err))
			}
		}
	} else if result.Status == models.AttestationStatusVerified {
		// Update device trust status
		if err := v.identitySvc.UpdateTrustStatus(ctx, result.DeviceID, "verified"); err != nil {
			v.logger.Error("Failed to update device trust status", zap.Error(err))
		}

		// Remove from quarantine if present
		v.Unquarantine(result.DeviceID)
	}

	return nil
}

// Quarantine adds a device to quarantine
func (v *Verifier) Quarantine(deviceID uuid.UUID, reason string) {
	v.quarantineMu.Lock()
	v.quarantinedDevices[deviceID] = time.Now()
	v.quarantineMu.Unlock()

	v.logger.Warn("Device quarantined",
		zap.String("device_id", deviceID.String()),
		zap.String("reason", reason),
	)
}

// Unquarantine removes a device from quarantine
func (v *Verifier) Unquarantine(deviceID uuid.UUID) {
	v.quarantineMu.Lock()
	delete(v.quarantinedDevices, deviceID)
	v.quarantineMu.Unlock()

	v.logger.Info("Device removed from quarantine",
		zap.String("device_id", deviceID.String()),
	)
}

// IsQuarantined checks if a device is quarantined
func (v *Verifier) IsQuarantined(deviceID uuid.UUID) bool {
	v.quarantineMu.RLock()
	defer v.quarantineMu.RUnlock()
	_, exists := v.quarantinedDevices[deviceID]
	return exists
}

// GetQuarantinedDevices returns list of quarantined devices
func (v *Verifier) GetQuarantinedDevices() []uuid.UUID {
	v.quarantineMu.RLock()
	defer v.quarantineMu.RUnlock()

	devices := make([]uuid.UUID, 0, len(v.quarantinedDevices))
	for id := range v.quarantinedDevices {
		devices = append(devices, id)
	}
	return devices
}

// GetLatestReport retrieves the latest attestation report for a device
func (v *Verifier) GetLatestReport(ctx context.Context, deviceID uuid.UUID) (*models.AttestationReport, error) {
	return v.repo.GetLatestReport(ctx, deviceID)
}

// ListReports retrieves attestation reports for a device
func (v *Verifier) ListReports(ctx context.Context, deviceID uuid.UUID, limit int) ([]*models.AttestationReport, error) {
	if limit <= 0 {
		limit = 50
	}
	return v.repo.ListReports(ctx, deviceID, limit)
}

// UpdateExpectedMeasurements updates expected measurements for a device
func (v *Verifier) UpdateExpectedMeasurements(ctx context.Context, expected *models.ExpectedMeasurements, updatedBy uuid.UUID) error {
	expected.UpdatedAt = time.Now()
	expected.UpdatedBy = updatedBy
	return v.repo.SaveExpectedMeasurements(ctx, expected)
}

// GetPolicy returns the current attestation policy
func (v *Verifier) GetPolicy() *models.AttestationPolicy {
	return v.policy
}

// UpdatePolicy updates the attestation policy
func (v *Verifier) UpdatePolicy(policy *models.AttestationPolicy) {
	policy.UpdatedAt = time.Now()
	v.policy = policy
}

// cleanupExpiredNonces periodically cleans up expired nonces
func (v *Verifier) cleanupExpiredNonces() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		v.nonceMu.Lock()
		now := time.Now()
		for nonce, entry := range v.nonceStore {
			if now.Sub(entry.createdAt) > v.nonceExpiry {
				delete(v.nonceStore, nonce)
			}
		}
		v.nonceMu.Unlock()
	}
}

// GenerateDeviceMeasurements generates measurement hashes for a device
// This is a utility function for device agents
func GenerateDeviceMeasurements(firmware, os, agent []byte, runningConfig, startupConfig string) *models.DeviceMeasurements {
	return &models.DeviceMeasurements{
		FirmwareHash:      hashBytes(firmware),
		OSHash:            hashBytes(os),
		AgentHash:         hashBytes(agent),
		RunningConfigHash: hashBytes([]byte(runningConfig)),
		StartupConfigHash: hashBytes([]byte(startupConfig)),
	}
}

func hashBytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyTPMSignature verifies a TPM signature (placeholder for TPM integration)
func (v *Verifier) VerifyTPMSignature(report *models.AttestationReport, aikPublicKey ed25519.PublicKey) bool {
	// In production, this would verify the TPM quote using the AIK
	// For now, return true if TPM signature exists
	return len(report.TPMSignature) > 0 && len(report.AIKCert) > 0
}
