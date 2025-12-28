package models

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AttestationType represents the type of attestation
type AttestationType string

const (
	AttestationTypeTPM      AttestationType = "tpm"      // Hardware TPM-based
	AttestationTypeSoftware AttestationType = "software" // Software-based
	AttestationTypeRemote   AttestationType = "remote"   // Remote attestation service
)

// AttestationStatus represents the result of attestation verification
type AttestationStatus string

const (
	AttestationStatusPending   AttestationStatus = "pending"
	AttestationStatusVerified  AttestationStatus = "verified"
	AttestationStatusFailed    AttestationStatus = "failed"
	AttestationStatusExpired   AttestationStatus = "expired"
	AttestationStatusUnknown   AttestationStatus = "unknown"
)

// AttestationReport represents a device attestation report
type AttestationReport struct {
	// Identity
	ID        uuid.UUID `json:"id"`
	DeviceID  uuid.UUID `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`

	// Attestation type
	Type AttestationType `json:"type"`

	// Measurements
	Measurements DeviceMeasurements `json:"measurements"`

	// TPM-specific (if applicable)
	PCRValues    map[int][]byte `json:"pcr_values,omitempty"`
	TPMSignature []byte         `json:"tpm_signature,omitempty"`
	AIKCert      []byte         `json:"aik_cert,omitempty"` // Attestation Identity Key certificate

	// Software-based signature (if no TPM)
	SoftwareSignature []byte `json:"software_signature,omitempty"`

	// Nonce for freshness
	Nonce []byte `json:"nonce"`

	// Quote data
	QuoteData []byte `json:"quote_data,omitempty"`
}

// DeviceMeasurements contains all measured values from the device
type DeviceMeasurements struct {
	// Boot chain
	FirmwareHash    []byte `json:"firmware_hash"`
	BootloaderHash  []byte `json:"bootloader_hash,omitempty"`
	OSHash          []byte `json:"os_hash"`
	KernelHash      []byte `json:"kernel_hash,omitempty"`

	// Configuration
	RunningConfigHash []byte `json:"running_config_hash"`
	StartupConfigHash []byte `json:"startup_config_hash"`
	AgentConfigHash   []byte `json:"agent_config_hash,omitempty"`

	// Software state
	AgentHash       []byte           `json:"agent_hash,omitempty"`
	ActiveProcesses []ProcessInfo    `json:"active_processes,omitempty"`
	LoadedModules   []ModuleInfo     `json:"loaded_modules,omitempty"`
	InstalledPackages []PackageInfo  `json:"installed_packages,omitempty"`

	// Network state
	OpenPorts     []PortInfo       `json:"open_ports,omitempty"`
	NetworkState  *NetworkStateInfo `json:"network_state,omitempty"`
	RoutingTable  []byte           `json:"routing_table_hash,omitempty"`
	ARPTable      []byte           `json:"arp_table_hash,omitempty"`

	// Security state
	CryptoKeys    []KeyInfo    `json:"crypto_keys,omitempty"`
	Certificates  []CertInfo   `json:"certificates,omitempty"`
	ACLs          []byte       `json:"acls_hash,omitempty"`
	FirewallRules []byte       `json:"firewall_rules_hash,omitempty"`

	// Hardware state
	HardwareSerial string          `json:"hardware_serial,omitempty"`
	CPUInfo        string          `json:"cpu_info,omitempty"`
	MemoryInfo     string          `json:"memory_info,omitempty"`
	InterfaceMACs  map[string]string `json:"interface_macs,omitempty"`

	// Additional measurements
	CustomMeasurements map[string][]byte `json:"custom_measurements,omitempty"`
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	Name       string `json:"name"`
	PID        int    `json:"pid"`
	User       string `json:"user,omitempty"`
	Command    string `json:"command,omitempty"`
	Hash       []byte `json:"hash,omitempty"` // Hash of executable
	StartTime  int64  `json:"start_time,omitempty"`
}

// ModuleInfo represents information about a loaded kernel module
type ModuleInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Hash    []byte `json:"hash,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

// PackageInfo represents installed package information
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Hash    []byte `json:"hash,omitempty"`
}

// PortInfo represents an open port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
	Process  string `json:"process,omitempty"`
	State    string `json:"state,omitempty"`
}

// NetworkStateInfo represents network state information
type NetworkStateInfo struct {
	Interfaces      []InterfaceInfo `json:"interfaces,omitempty"`
	ActiveConns     int             `json:"active_connections"`
	ListeningPorts  int             `json:"listening_ports"`
}

// InterfaceInfo represents interface state
type InterfaceInfo struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips,omitempty"`
	State      string   `json:"state"`
	MTU        int      `json:"mtu,omitempty"`
}

// KeyInfo represents cryptographic key information
type KeyInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // rsa, ec, ed25519
	Size        int       `json:"size,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Usage       string    `json:"usage,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// CertInfo represents certificate information
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

// Hash computes the hash of the attestation report
func (ar *AttestationReport) Hash() []byte {
	h := sha256.New()

	h.Write(ar.ID[:])
	h.Write(ar.DeviceID[:])
	binary.Write(h, binary.BigEndian, ar.Timestamp.UnixNano())
	h.Write([]byte(ar.Type))

	// Measurements
	measurementsJSON, _ := json.Marshal(ar.Measurements)
	h.Write(measurementsJSON)

	// PCR values
	if ar.PCRValues != nil {
		for i := 0; i < 24; i++ {
			if val, ok := ar.PCRValues[i]; ok {
				binary.Write(h, binary.BigEndian, int32(i))
				h.Write(val)
			}
		}
	}

	// Nonce
	h.Write(ar.Nonce)

	return h.Sum(nil)
}

// Sign signs the attestation report with software key
func (ar *AttestationReport) Sign(privateKey ed25519.PrivateKey) {
	hash := ar.Hash()
	ar.SoftwareSignature = ed25519.Sign(privateKey, hash)
}

// VerifySoftwareSignature verifies the software signature
func (ar *AttestationReport) VerifySoftwareSignature(publicKey ed25519.PublicKey) bool {
	hash := ar.Hash()
	return ed25519.Verify(publicKey, hash, ar.SoftwareSignature)
}

// ExpectedMeasurements represents expected measurements for verification
type ExpectedMeasurements struct {
	DeviceID uuid.UUID `json:"device_id"`

	// Expected hashes
	FirmwareHash      []byte `json:"firmware_hash,omitempty"`
	OSHash            []byte `json:"os_hash,omitempty"`
	AgentHash         []byte `json:"agent_hash,omitempty"`

	// Expected PCR values
	ExpectedPCRs map[int][]byte `json:"expected_pcrs,omitempty"`

	// Allowed processes (by name or hash)
	AllowedProcesses  []string `json:"allowed_processes,omitempty"`
	AllowedProcessHashes [][]byte `json:"allowed_process_hashes,omitempty"`

	// Allowed modules
	AllowedModules    []string `json:"allowed_modules,omitempty"`

	// Expected open ports
	ExpectedPorts     []PortInfo `json:"expected_ports,omitempty"`

	// Version requirements
	MinOSVersion      string `json:"min_os_version,omitempty"`
	MinAgentVersion   string `json:"min_agent_version,omitempty"`
	MinFirmwareVersion string `json:"min_firmware_version,omitempty"`

	// Last updated
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy uuid.UUID `json:"updated_by"`
}

// AttestationVerificationResult represents the result of attestation verification
type AttestationVerificationResult struct {
	DeviceID       uuid.UUID         `json:"device_id"`
	ReportID       uuid.UUID         `json:"report_id"`
	Status         AttestationStatus `json:"status"`
	VerifiedAt     time.Time         `json:"verified_at"`

	// Detailed results
	SignatureValid   bool `json:"signature_valid"`
	NonceValid       bool `json:"nonce_valid"`
	MeasurementsValid bool `json:"measurements_valid"`
	PCRsValid        bool `json:"pcrs_valid,omitempty"`

	// Mismatches
	Mismatches []AttestationMismatch `json:"mismatches,omitempty"`

	// Warnings (non-fatal issues)
	Warnings []string `json:"warnings,omitempty"`

	// Recommended action
	RecommendedAction string `json:"recommended_action,omitempty"`
}

// AttestationMismatch represents a specific measurement mismatch
type AttestationMismatch struct {
	Field    string `json:"field"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Severity string `json:"severity"` // critical, warning, info
	Message  string `json:"message"`
}

// AttestationRequest represents a request for device attestation
type AttestationRequest struct {
	DeviceID       uuid.UUID `json:"device_id"`
	Nonce          []byte    `json:"nonce"`           // Server-generated nonce
	RequestedPCRs  []int     `json:"requested_pcrs,omitempty"` // Which PCRs to include
	IncludeDetails bool      `json:"include_details"` // Include process/module lists
	Timeout        int       `json:"timeout_seconds,omitempty"`
}

// AttestationPolicy defines attestation requirements
type AttestationPolicy struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`

	// When to attest
	AttestOnConnect    bool `json:"attest_on_connect"`
	AttestOnConfigChange bool `json:"attest_on_config_change"`
	PeriodicIntervalMinutes int `json:"periodic_interval_minutes,omitempty"`

	// What to verify
	VerifyFirmware     bool `json:"verify_firmware"`
	VerifyOS           bool `json:"verify_os"`
	VerifyConfig       bool `json:"verify_config"`
	VerifyProcesses    bool `json:"verify_processes"`
	VerifyPorts        bool `json:"verify_ports"`
	RequireTPM         bool `json:"require_tpm"`

	// PCRs to verify (for TPM)
	RequiredPCRs []int `json:"required_pcrs,omitempty"`

	// Actions on failure
	ActionOnFailure    AttestationFailureAction `json:"action_on_failure"`
	AlertOnFailure     bool `json:"alert_on_failure"`
	QuarantineOnFailure bool `json:"quarantine_on_failure"`

	// Applicable devices
	ApplicableRoles       []DeviceRole        `json:"applicable_roles,omitempty"`
	ApplicableCriticality []DeviceCriticality `json:"applicable_criticality,omitempty"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AttestationFailureAction defines what to do on attestation failure
type AttestationFailureAction string

const (
	AttestationFailureLog        AttestationFailureAction = "log"
	AttestationFailureAlert      AttestationFailureAction = "alert"
	AttestationFailureQuarantine AttestationFailureAction = "quarantine"
	AttestationFailureDisconnect AttestationFailureAction = "disconnect"
)

// NewAttestationReport creates a new attestation report
func NewAttestationReport(deviceID uuid.UUID, attestType AttestationType, nonce []byte) *AttestationReport {
	return &AttestationReport{
		ID:        uuid.New(),
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Type:      attestType,
		Nonce:     nonce,
	}
}

// Verify performs basic verification of the attestation report
func (ar *AttestationReport) Verify(expected *ExpectedMeasurements, publicKey ed25519.PublicKey) *AttestationVerificationResult {
	result := &AttestationVerificationResult{
		DeviceID:   ar.DeviceID,
		ReportID:   ar.ID,
		VerifiedAt: time.Now().UTC(),
		Status:     AttestationStatusVerified,
	}

	// Verify signature
	if ar.Type == AttestationTypeSoftware {
		result.SignatureValid = ar.VerifySoftwareSignature(publicKey)
		if !result.SignatureValid {
			result.Status = AttestationStatusFailed
			result.Mismatches = append(result.Mismatches, AttestationMismatch{
				Field:    "signature",
				Severity: "critical",
				Message:  "Software signature verification failed",
			})
			return result
		}
	}

	result.NonceValid = true // Nonce validation would be done by caller

	// Verify measurements
	result.MeasurementsValid = true

	if expected != nil {
		// Check firmware hash
		if expected.FirmwareHash != nil && !bytesEqual(expected.FirmwareHash, ar.Measurements.FirmwareHash) {
			result.MeasurementsValid = false
			result.Mismatches = append(result.Mismatches, AttestationMismatch{
				Field:    "firmware_hash",
				Severity: "critical",
				Message:  "Firmware hash mismatch",
			})
		}

		// Check OS hash
		if expected.OSHash != nil && !bytesEqual(expected.OSHash, ar.Measurements.OSHash) {
			result.MeasurementsValid = false
			result.Mismatches = append(result.Mismatches, AttestationMismatch{
				Field:    "os_hash",
				Severity: "critical",
				Message:  "OS hash mismatch",
			})
		}

		// Check agent hash
		if expected.AgentHash != nil && !bytesEqual(expected.AgentHash, ar.Measurements.AgentHash) {
			result.MeasurementsValid = false
			result.Mismatches = append(result.Mismatches, AttestationMismatch{
				Field:    "agent_hash",
				Severity: "critical",
				Message:  "Agent hash mismatch",
			})
		}

		// Check PCRs
		if expected.ExpectedPCRs != nil && ar.PCRValues != nil {
			result.PCRsValid = true
			for pcr, expectedValue := range expected.ExpectedPCRs {
				if actualValue, ok := ar.PCRValues[pcr]; ok {
					if !bytesEqual(expectedValue, actualValue) {
						result.PCRsValid = false
						result.Mismatches = append(result.Mismatches, AttestationMismatch{
							Field:    "pcr_" + string(rune('0'+pcr)),
							Severity: "critical",
							Message:  "PCR value mismatch",
						})
					}
				} else {
					result.PCRsValid = false
					result.Mismatches = append(result.Mismatches, AttestationMismatch{
						Field:    "pcr_" + string(rune('0'+pcr)),
						Severity: "critical",
						Message:  "PCR value missing",
					})
				}
			}
		}
	}

	// Set final status
	if !result.SignatureValid || !result.MeasurementsValid {
		result.Status = AttestationStatusFailed
		result.RecommendedAction = "quarantine"
	} else if len(result.Warnings) > 0 {
		result.RecommendedAction = "review"
	}

	return result
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

// DefaultAttestationPolicy returns a default attestation policy
func DefaultAttestationPolicy() *AttestationPolicy {
	return &AttestationPolicy{
		ID:                     uuid.New(),
		Name:                   "default",
		Description:            "Default attestation policy",
		AttestOnConnect:        true,
		AttestOnConfigChange:   true,
		PeriodicIntervalMinutes: 60,
		VerifyFirmware:         true,
		VerifyOS:               true,
		VerifyConfig:           true,
		VerifyProcesses:        false,
		VerifyPorts:            false,
		RequireTPM:             false,
		ActionOnFailure:        AttestationFailureAlert,
		AlertOnFailure:         true,
		QuarantineOnFailure:    false,
		CreatedAt:              time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}
}
