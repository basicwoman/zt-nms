package audit

import (
	"context"
	"crypto/ed25519"
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
	ErrEventNotFound      = errors.New("audit event not found")
	ErrChainBroken        = errors.New("audit chain integrity compromised")
	ErrInvalidEventHash   = errors.New("event hash verification failed")
	ErrSequenceGap        = errors.New("sequence number gap detected")
	ErrEventAlreadyExists = errors.New("event with this ID already exists")
)

// Repository interface for audit persistence
type Repository interface {
	Append(ctx context.Context, event *models.AuditEvent) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AuditEvent, error)
	GetBySequence(ctx context.Context, sequence int64) (*models.AuditEvent, error)
	GetLastEvent(ctx context.Context) (*models.AuditEvent, error)
	Query(ctx context.Context, query *models.AuditQuery) ([]*models.AuditEvent, int, error)
	GetEventRange(ctx context.Context, fromSeq, toSeq int64) ([]*models.AuditEvent, error)
	GetStats(ctx context.Context, from, to time.Time) (*AuditStats, error)
}

// Notifier interface for alerts
type Notifier interface {
	SendAlert(ctx context.Context, alertType string, message string, severity string, details map[string]interface{}) error
}

// Service provides audit logging operations
type Service struct {
	repo       Repository
	notifier   Notifier
	logger     *zap.Logger
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// Chain state
	lastEvent  *models.AuditEvent
	sequence   int64
	mu         sync.Mutex

	// Retention policy
	retentionPolicy *models.AuditRetentionPolicy

	// Metrics
	eventsLogged int64
	chainValid   bool
}

// AuditStats contains audit statistics
type AuditStats struct {
	TotalEvents       int64                      `json:"total_events"`
	EventsByType      map[models.AuditEventType]int64 `json:"events_by_type"`
	EventsBySeverity  map[models.AuditSeverity]int64  `json:"events_by_severity"`
	EventsByResult    map[models.AuditResult]int64    `json:"events_by_result"`
	SecurityEvents    int64                      `json:"security_events"`
	FailedAuthEvents  int64                      `json:"failed_auth_events"`
	DeniedAccessEvents int64                     `json:"denied_access_events"`
}

// Config contains service configuration
type Config struct {
	PrivateKey      ed25519.PrivateKey
	PublicKey       ed25519.PublicKey
	RetentionPolicy *models.AuditRetentionPolicy
}

// NewService creates a new audit service
func NewService(repo Repository, notifier Notifier, logger *zap.Logger, config *Config) (*Service, error) {
	s := &Service{
		repo:       repo,
		notifier:   notifier,
		logger:     logger,
		chainValid: true,
	}

	if config != nil {
		s.privateKey = config.PrivateKey
		s.publicKey = config.PublicKey
		s.retentionPolicy = config.RetentionPolicy
	}

	if s.retentionPolicy == nil {
		s.retentionPolicy = models.DefaultAuditRetentionPolicy()
	}

	// Initialize chain state from last event
	lastEvent, err := repo.GetLastEvent(context.Background())
	if err == nil && lastEvent != nil {
		s.lastEvent = lastEvent
		s.sequence = lastEvent.Sequence
	}

	return s, nil
}

// Log creates a new audit event
func (s *Service) Log(ctx context.Context, builder *models.AuditEventBuilder) (*models.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get previous hash
	var prevHash []byte
	if s.lastEvent != nil {
		prevHash = s.lastEvent.EventHash
	}

	// Build event with sequence and prev hash
	s.sequence++
	event := builder.Build(s.sequence, prevHash)

	// Sign the event if we have a private key
	if s.privateKey != nil {
		signature := ed25519.Sign(s.privateKey, event.EventHash)
		event.OperationSignature = signature
	}

	// Append to repository
	if err := s.repo.Append(ctx, event); err != nil {
		s.sequence--
		return nil, err
	}

	// Update last event
	s.lastEvent = event
	s.eventsLogged++

	// Check for security events that need alerting
	s.checkSecurityAlert(ctx, event)

	s.logger.Debug("Audit event logged",
		zap.String("event_id", event.ID.String()),
		zap.Int64("sequence", event.Sequence),
		zap.String("event_type", string(event.EventType)),
	)

	return event, nil
}

// LogIdentityEvent logs an identity-related event
func (s *Service) LogIdentityEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	identity *models.Identity,
	actor *uuid.UUID,
	result models.AuditResult,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithResult(result)

	if identity != nil {
		builder.WithResource("identity", identity.ID, string(identity.Type))
	}

	if actor != nil {
		builder.WithActor(*actor, models.IdentityTypeOperator, "")
	}

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	// Set severity based on event type
	switch eventType {
	case models.AuditEventIdentityAuthFailed:
		builder.WithSeverity(models.AuditSeverityWarning)
		builder.WithSecurityFlag("auth_failure")
	case models.AuditEventIdentityDelete:
		builder.WithSeverity(models.AuditSeverityWarning)
	default:
		builder.WithSeverity(models.AuditSeverityInfo)
	}

	_, err := s.Log(ctx, builder)
	return err
}

// LogCapabilityEvent logs a capability-related event
func (s *Service) LogCapabilityEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	capabilityID uuid.UUID,
	actor *uuid.UUID,
	result models.AuditResult,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithResult(result).
		WithResource("capability", capabilityID, "").
		WithCapability(capabilityID)

	if actor != nil {
		builder.WithActor(*actor, models.IdentityTypeOperator, "")
	}

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	switch eventType {
	case models.AuditEventCapabilityRevoke:
		builder.WithSeverity(models.AuditSeverityWarning)
	default:
		builder.WithSeverity(models.AuditSeverityInfo)
	}

	_, err := s.Log(ctx, builder)
	return err
}

// LogOperationEvent logs an operation-related event
func (s *Service) LogOperationEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	operationID uuid.UUID,
	deviceID uuid.UUID,
	actor *uuid.UUID,
	result models.AuditResult,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithResult(result).
		WithResource("device", deviceID, "").
		WithOperation(operationID)

	if actor != nil {
		builder.WithActor(*actor, models.IdentityTypeOperator, "")
	}

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	switch eventType {
	case models.AuditEventOperationDenied:
		builder.WithSeverity(models.AuditSeverityWarning)
		builder.WithSecurityFlag("access_denied")
	case models.AuditEventOperationFailed:
		builder.WithSeverity(models.AuditSeverityError)
	default:
		builder.WithSeverity(models.AuditSeverityInfo)
	}

	_, err := s.Log(ctx, builder)
	return err
}

// LogConfigEvent logs a configuration-related event
func (s *Service) LogConfigEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	deviceID uuid.UUID,
	actor *uuid.UUID,
	result models.AuditResult,
	configDiff *models.ConfigDiff,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithResult(result).
		WithResource("device", deviceID, "")

	if actor != nil {
		builder.WithActor(*actor, models.IdentityTypeOperator, "")
	}

	if configDiff != nil {
		builder.WithConfigChange(nil, nil, configDiff)
	}

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	switch eventType {
	case models.AuditEventConfigDeploy:
		builder.WithSeverity(models.AuditSeverityInfo)
	case models.AuditEventConfigRollback:
		builder.WithSeverity(models.AuditSeverityWarning)
	default:
		builder.WithSeverity(models.AuditSeverityInfo)
	}

	_, err := s.Log(ctx, builder)
	return err
}

// LogAttestationEvent logs an attestation-related event
func (s *Service) LogAttestationEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	deviceID uuid.UUID,
	result models.AuditResult,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithResult(result).
		WithResource("device", deviceID, "")

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	switch eventType {
	case models.AuditEventDeviceAttestFail:
		builder.WithSeverity(models.AuditSeverityCritical)
		builder.WithSecurityFlag("attestation_failure")
	default:
		builder.WithSeverity(models.AuditSeverityInfo)
	}

	_, err := s.Log(ctx, builder)
	return err
}

// LogSecurityEvent logs a security event
func (s *Service) LogSecurityEvent(
	ctx context.Context,
	eventType models.AuditEventType,
	severity models.AuditSeverity,
	actor *uuid.UUID,
	resourceType string,
	resourceID *uuid.UUID,
	details map[string]interface{},
) error {
	builder := models.NewAuditEventBuilder(eventType).
		WithSeverity(severity).
		WithResult(models.AuditResultFailure)

	if actor != nil {
		builder.WithActor(*actor, models.IdentityTypeOperator, "")
	}

	if resourceID != nil {
		builder.WithResource(resourceType, *resourceID, "")
	}

	if details != nil {
		for k, v := range details {
			builder.WithContext(k, v)
		}
	}

	builder.WithSecurityFlag("security_event")

	_, err := s.Log(ctx, builder)
	return err
}

// GetEvent retrieves an audit event by ID
func (s *Service) GetEvent(ctx context.Context, id uuid.UUID) (*models.AuditEvent, error) {
	return s.repo.GetByID(ctx, id)
}

// Query queries audit events
func (s *Service) Query(ctx context.Context, query *models.AuditQuery) ([]*models.AuditEvent, int, error) {
	if query.Limit == 0 {
		query.Limit = 50
	}
	if query.Limit > 1000 {
		query.Limit = 1000
	}
	return s.repo.Query(ctx, query)
}

// VerifyChain verifies the integrity of the audit chain
func (s *Service) VerifyChain(ctx context.Context, fromSeq, toSeq int64) (*models.AuditChainVerification, error) {
	result := &models.AuditChainVerification{
		Valid:         true,
		FirstSequence: fromSeq,
		LastSequence:  toSeq,
		VerifiedAt:    time.Now().UTC(),
	}

	events, err := s.repo.GetEventRange(ctx, fromSeq, toSeq)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result, err
	}

	result.EventCount = len(events)

	if len(events) == 0 {
		return result, nil
	}

	// Verify each event
	var prevEvent *models.AuditEvent
	for i, event := range events {
		// Verify event hash
		if !event.Verify() {
			result.Valid = false
			result.BrokenAt = &event.Sequence
			result.Error = "event hash verification failed at sequence " + hex.EncodeToString([]byte{byte(event.Sequence)})
			s.chainValid = false
			return result, nil
		}

		// Verify chain link
		if i > 0 {
			if !event.VerifyChain(prevEvent) {
				result.Valid = false
				result.BrokenAt = &event.Sequence
				result.Error = "chain link verification failed at sequence " + hex.EncodeToString([]byte{byte(event.Sequence)})
				s.chainValid = false
				return result, nil
			}
		}

		// Verify signature if we have a public key
		if s.publicKey != nil && event.OperationSignature != nil {
			if !ed25519.Verify(s.publicKey, event.EventHash, event.OperationSignature) {
				result.Valid = false
				result.BrokenAt = &event.Sequence
				result.Error = "signature verification failed at sequence " + hex.EncodeToString([]byte{byte(event.Sequence)})
				return result, nil
			}
		}

		prevEvent = event
	}

	s.chainValid = true
	return result, nil
}

// VerifyEvent verifies a single audit event
func (s *Service) VerifyEvent(ctx context.Context, id uuid.UUID) (bool, error) {
	event, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return false, err
	}

	// Verify hash
	if !event.Verify() {
		return false, ErrInvalidEventHash
	}

	// Get previous event to verify chain
	if event.Sequence > 1 {
		prevEvent, err := s.repo.GetBySequence(ctx, event.Sequence-1)
		if err != nil {
			return false, err
		}
		if !event.VerifyChain(prevEvent) {
			return false, ErrChainBroken
		}
	}

	return true, nil
}

// GetStats returns audit statistics
func (s *Service) GetStats(ctx context.Context, from, to time.Time) (*AuditStats, error) {
	return s.repo.GetStats(ctx, from, to)
}

// Export exports audit events for a query
func (s *Service) Export(ctx context.Context, query *models.AuditQuery, exportedBy uuid.UUID) (*models.AuditExport, error) {
	events, total, err := s.repo.Query(ctx, query)
	if err != nil {
		return nil, err
	}

	// Verify chain for exported events
	chainValid := true
	if len(events) > 1 {
		for i := 1; i < len(events); i++ {
			if !events[i].VerifyChain(events[i-1]) {
				chainValid = false
				break
			}
		}
	}

	export := &models.AuditExport{
		ExportID:   uuid.New(),
		ExportedAt: time.Now().UTC(),
		ExportedBy: exportedBy,
		Query:      *query,
		Events:     make([]models.AuditEvent, len(events)),
		TotalCount: total,
		ChainValid: chainValid,
	}

	for i, e := range events {
		export.Events[i] = *e
	}

	// Sign the export if we have a private key
	if s.privateKey != nil {
		h := sha256.New()
		for _, e := range export.Events {
			h.Write(e.EventHash)
		}
		export.Signature = ed25519.Sign(s.privateKey, h.Sum(nil))
	}

	return export, nil
}

// checkSecurityAlert checks if an event requires alerting
func (s *Service) checkSecurityAlert(ctx context.Context, event *models.AuditEvent) {
	if s.notifier == nil {
		return
	}

	shouldAlert := false
	alertSeverity := "info"
	alertMessage := ""

	switch event.EventType {
	case models.AuditEventSecurityAlert, models.AuditEventSecurityIncident, models.AuditEventSecurityViolation:
		shouldAlert = true
		alertSeverity = "critical"
		alertMessage = "Security event detected: " + string(event.EventType)

	case models.AuditEventDeviceAttestFail:
		shouldAlert = true
		alertSeverity = "critical"
		alertMessage = "Device attestation failed"

	case models.AuditEventIdentityAuthFailed:
		// Could implement rate limiting to alert on multiple failures
		if event.Details.Context != nil {
			if count, ok := event.Details.Context["consecutive_failures"].(int); ok && count >= 5 {
				shouldAlert = true
				alertSeverity = "warning"
				alertMessage = "Multiple authentication failures detected"
			}
		}

	case models.AuditEventOperationDenied:
		if event.Severity == models.AuditSeverityCritical {
			shouldAlert = true
			alertSeverity = "warning"
			alertMessage = "Critical operation denied"
		}
	}

	if shouldAlert {
		details := map[string]interface{}{
			"event_id":   event.ID,
			"event_type": event.EventType,
			"timestamp":  event.Timestamp,
		}
		if event.ActorID != nil {
			details["actor_id"] = event.ActorID
		}
		if event.ResourceID != nil {
			details["resource_id"] = event.ResourceID
		}

		if err := s.notifier.SendAlert(ctx, string(event.EventType), alertMessage, alertSeverity, details); err != nil {
			s.logger.Error("Failed to send security alert", zap.Error(err))
		}
	}
}

// IsChainValid returns whether the audit chain is valid
func (s *Service) IsChainValid() bool {
	return s.chainValid
}

// GetEventsLogged returns the number of events logged
func (s *Service) GetEventsLogged() int64 {
	return s.eventsLogged
}

// GetRetentionPolicy returns the retention policy
func (s *Service) GetRetentionPolicy() *models.AuditRetentionPolicy {
	return s.retentionPolicy
}
