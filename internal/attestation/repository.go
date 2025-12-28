package attestation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/uuid"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// SaveReport saves an attestation report
func (r *PostgresRepository) SaveReport(ctx context.Context, report *models.AttestationReport) error {
	measurementsJSON, err := json.Marshal(report.Measurements)
	if err != nil {
		return err
	}

	pcrValuesJSON, err := json.Marshal(report.PCRValues)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO attestation_reports (
			id, device_id, timestamp, type, measurements, pcr_values,
			tpm_signature, aik_cert, software_signature, nonce, quote_data
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = r.db.ExecContext(ctx, query,
		report.ID,
		report.DeviceID,
		report.Timestamp,
		report.Type,
		measurementsJSON,
		pcrValuesJSON,
		report.TPMSignature,
		report.AIKCert,
		report.SoftwareSignature,
		report.Nonce,
		report.QuoteData,
	)
	return err
}

// GetReport retrieves an attestation report by ID
func (r *PostgresRepository) GetReport(ctx context.Context, id uuid.UUID) (*models.AttestationReport, error) {
	query := `
		SELECT id, device_id, timestamp, type, measurements, pcr_values,
			   tpm_signature, aik_cert, software_signature, nonce, quote_data
		FROM attestation_reports
		WHERE id = $1
	`

	var report models.AttestationReport
	var measurementsJSON, pcrValuesJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&report.ID,
		&report.DeviceID,
		&report.Timestamp,
		&report.Type,
		&measurementsJSON,
		&pcrValuesJSON,
		&report.TPMSignature,
		&report.AIKCert,
		&report.SoftwareSignature,
		&report.Nonce,
		&report.QuoteData,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}

	if err := json.Unmarshal(measurementsJSON, &report.Measurements); err != nil {
		return nil, err
	}
	if len(pcrValuesJSON) > 0 {
		if err := json.Unmarshal(pcrValuesJSON, &report.PCRValues); err != nil {
			return nil, err
		}
	}

	return &report, nil
}

// GetLatestReport retrieves the latest attestation report for a device
func (r *PostgresRepository) GetLatestReport(ctx context.Context, deviceID uuid.UUID) (*models.AttestationReport, error) {
	query := `
		SELECT id, device_id, timestamp, type, measurements, pcr_values,
			   tpm_signature, aik_cert, software_signature, nonce, quote_data
		FROM attestation_reports
		WHERE device_id = $1
		ORDER BY timestamp DESC
		LIMIT 1
	`

	var report models.AttestationReport
	var measurementsJSON, pcrValuesJSON []byte

	err := r.db.QueryRowContext(ctx, query, deviceID).Scan(
		&report.ID,
		&report.DeviceID,
		&report.Timestamp,
		&report.Type,
		&measurementsJSON,
		&pcrValuesJSON,
		&report.TPMSignature,
		&report.AIKCert,
		&report.SoftwareSignature,
		&report.Nonce,
		&report.QuoteData,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}

	if err := json.Unmarshal(measurementsJSON, &report.Measurements); err != nil {
		return nil, err
	}
	if len(pcrValuesJSON) > 0 {
		if err := json.Unmarshal(pcrValuesJSON, &report.PCRValues); err != nil {
			return nil, err
		}
	}

	return &report, nil
}

// ListReports retrieves attestation reports for a device
func (r *PostgresRepository) ListReports(ctx context.Context, deviceID uuid.UUID, limit int) ([]*models.AttestationReport, error) {
	query := `
		SELECT id, device_id, timestamp, type, measurements, pcr_values,
			   tpm_signature, aik_cert, software_signature, nonce, quote_data
		FROM attestation_reports
		WHERE device_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*models.AttestationReport
	for rows.Next() {
		var report models.AttestationReport
		var measurementsJSON, pcrValuesJSON []byte

		err := rows.Scan(
			&report.ID,
			&report.DeviceID,
			&report.Timestamp,
			&report.Type,
			&measurementsJSON,
			&pcrValuesJSON,
			&report.TPMSignature,
			&report.AIKCert,
			&report.SoftwareSignature,
			&report.Nonce,
			&report.QuoteData,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(measurementsJSON, &report.Measurements); err != nil {
			return nil, err
		}
		if len(pcrValuesJSON) > 0 {
			if err := json.Unmarshal(pcrValuesJSON, &report.PCRValues); err != nil {
				return nil, err
			}
		}

		reports = append(reports, &report)
	}

	return reports, rows.Err()
}

// SaveExpectedMeasurements saves expected measurements for a device
func (r *PostgresRepository) SaveExpectedMeasurements(ctx context.Context, expected *models.ExpectedMeasurements) error {
	allowedProcessHashes, _ := json.Marshal(expected.AllowedProcessHashes)
	expectedPCRs, _ := json.Marshal(expected.ExpectedPCRs)
	expectedPorts, _ := json.Marshal(expected.ExpectedPorts)

	query := `
		INSERT INTO expected_measurements (
			device_id, firmware_hash, os_hash, agent_hash, expected_pcrs,
			allowed_processes, allowed_process_hashes, allowed_modules, expected_ports,
			min_os_version, min_agent_version, min_firmware_version, updated_at, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (device_id) DO UPDATE SET
			firmware_hash = EXCLUDED.firmware_hash,
			os_hash = EXCLUDED.os_hash,
			agent_hash = EXCLUDED.agent_hash,
			expected_pcrs = EXCLUDED.expected_pcrs,
			allowed_processes = EXCLUDED.allowed_processes,
			allowed_process_hashes = EXCLUDED.allowed_process_hashes,
			allowed_modules = EXCLUDED.allowed_modules,
			expected_ports = EXCLUDED.expected_ports,
			min_os_version = EXCLUDED.min_os_version,
			min_agent_version = EXCLUDED.min_agent_version,
			min_firmware_version = EXCLUDED.min_firmware_version,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by
	`

	_, err := r.db.ExecContext(ctx, query,
		expected.DeviceID,
		expected.FirmwareHash,
		expected.OSHash,
		expected.AgentHash,
		expectedPCRs,
		expected.AllowedProcesses,
		allowedProcessHashes,
		expected.AllowedModules,
		expectedPorts,
		expected.MinOSVersion,
		expected.MinAgentVersion,
		expected.MinFirmwareVersion,
		expected.UpdatedAt,
		expected.UpdatedBy,
	)
	return err
}

// GetExpectedMeasurements retrieves expected measurements for a device
func (r *PostgresRepository) GetExpectedMeasurements(ctx context.Context, deviceID uuid.UUID) (*models.ExpectedMeasurements, error) {
	query := `
		SELECT device_id, firmware_hash, os_hash, agent_hash, expected_pcrs,
			   allowed_processes, allowed_process_hashes, allowed_modules, expected_ports,
			   min_os_version, min_agent_version, min_firmware_version, updated_at, updated_by
		FROM expected_measurements
		WHERE device_id = $1
	`

	var expected models.ExpectedMeasurements
	var expectedPCRs, allowedProcessHashes, expectedPorts []byte

	err := r.db.QueryRowContext(ctx, query, deviceID).Scan(
		&expected.DeviceID,
		&expected.FirmwareHash,
		&expected.OSHash,
		&expected.AgentHash,
		&expectedPCRs,
		&expected.AllowedProcesses,
		&allowedProcessHashes,
		&expected.AllowedModules,
		&expectedPorts,
		&expected.MinOSVersion,
		&expected.MinAgentVersion,
		&expected.MinFirmwareVersion,
		&expected.UpdatedAt,
		&expected.UpdatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMissingExpectedMeasurements
		}
		return nil, err
	}

	if len(expectedPCRs) > 0 {
		json.Unmarshal(expectedPCRs, &expected.ExpectedPCRs)
	}
	if len(allowedProcessHashes) > 0 {
		json.Unmarshal(allowedProcessHashes, &expected.AllowedProcessHashes)
	}
	if len(expectedPorts) > 0 {
		json.Unmarshal(expectedPorts, &expected.ExpectedPorts)
	}

	return &expected, nil
}

// SaveVerificationResult saves an attestation verification result
func (r *PostgresRepository) SaveVerificationResult(ctx context.Context, result *models.AttestationVerificationResult) error {
	mismatchesJSON, _ := json.Marshal(result.Mismatches)

	query := `
		INSERT INTO attestation_results (
			device_id, report_id, status, verified_at, signature_valid,
			nonce_valid, measurements_valid, pcrs_valid, mismatches, warnings, recommended_action
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.ExecContext(ctx, query,
		result.DeviceID,
		result.ReportID,
		result.Status,
		result.VerifiedAt,
		result.SignatureValid,
		result.NonceValid,
		result.MeasurementsValid,
		result.PCRsValid,
		mismatchesJSON,
		result.Warnings,
		result.RecommendedAction,
	)
	return err
}

// InMemoryRepository implements Repository using in-memory storage (for testing)
type InMemoryRepository struct {
	reports              map[uuid.UUID]*models.AttestationReport
	reportsByDevice      map[uuid.UUID][]*models.AttestationReport
	expectedMeasurements map[uuid.UUID]*models.ExpectedMeasurements
	results              []*models.AttestationVerificationResult
	mu                   sync.RWMutex
}

// NewInMemoryRepository creates a new in-memory repository
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		reports:              make(map[uuid.UUID]*models.AttestationReport),
		reportsByDevice:      make(map[uuid.UUID][]*models.AttestationReport),
		expectedMeasurements: make(map[uuid.UUID]*models.ExpectedMeasurements),
		results:              make([]*models.AttestationVerificationResult, 0),
	}
}

// SaveReport saves an attestation report (in-memory)
func (r *InMemoryRepository) SaveReport(ctx context.Context, report *models.AttestationReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.reports[report.ID] = report
	r.reportsByDevice[report.DeviceID] = append(r.reportsByDevice[report.DeviceID], report)
	return nil
}

// GetReport retrieves an attestation report by ID (in-memory)
func (r *InMemoryRepository) GetReport(ctx context.Context, id uuid.UUID) (*models.AttestationReport, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	report, exists := r.reports[id]
	if !exists {
		return nil, ErrDeviceNotFound
	}
	return report, nil
}

// GetLatestReport retrieves the latest attestation report for a device (in-memory)
func (r *InMemoryRepository) GetLatestReport(ctx context.Context, deviceID uuid.UUID) (*models.AttestationReport, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reports, exists := r.reportsByDevice[deviceID]
	if !exists || len(reports) == 0 {
		return nil, ErrDeviceNotFound
	}

	// Find latest by timestamp
	var latest *models.AttestationReport
	for _, report := range reports {
		if latest == nil || report.Timestamp.After(latest.Timestamp) {
			latest = report
		}
	}
	return latest, nil
}

// ListReports retrieves attestation reports for a device (in-memory)
func (r *InMemoryRepository) ListReports(ctx context.Context, deviceID uuid.UUID, limit int) ([]*models.AttestationReport, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reports, exists := r.reportsByDevice[deviceID]
	if !exists {
		return []*models.AttestationReport{}, nil
	}

	// Sort by timestamp descending
	result := make([]*models.AttestationReport, len(reports))
	copy(result, reports)

	// Simple bubble sort for small lists
	for i := 0; i < len(result)-1; i++ {
		for j := 0; j < len(result)-i-1; j++ {
			if result[j].Timestamp.Before(result[j+1].Timestamp) {
				result[j], result[j+1] = result[j+1], result[j]
			}
		}
	}

	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}

	return result, nil
}

// SaveExpectedMeasurements saves expected measurements (in-memory)
func (r *InMemoryRepository) SaveExpectedMeasurements(ctx context.Context, expected *models.ExpectedMeasurements) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.expectedMeasurements[expected.DeviceID] = expected
	return nil
}

// GetExpectedMeasurements retrieves expected measurements (in-memory)
func (r *InMemoryRepository) GetExpectedMeasurements(ctx context.Context, deviceID uuid.UUID) (*models.ExpectedMeasurements, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	expected, exists := r.expectedMeasurements[deviceID]
	if !exists {
		return nil, ErrMissingExpectedMeasurements
	}
	return expected, nil
}

// SaveVerificationResult saves a verification result (in-memory)
func (r *InMemoryRepository) SaveVerificationResult(ctx context.Context, result *models.AttestationVerificationResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.results = append(r.results, result)
	return nil
}
