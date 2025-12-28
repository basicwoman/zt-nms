package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/audit"
	"github.com/basicwoman/zt-nms/pkg/models"
)

func createTestBuilder(eventType models.AuditEventType) *models.AuditEventBuilder {
	actorID := uuid.New()
	resourceID := uuid.New()
	return models.NewAuditEventBuilder(eventType).
		WithActor(actorID, models.IdentityTypeOperator, "test-user").
		WithResource("identity", resourceID, "test-resource").
		WithResult(models.AuditResultSuccess)
}

func createService(t *testing.T) (*audit.Service, *audit.InMemoryRepository) {
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()

	service, err := audit.NewService(repo, nil, logger, nil)
	require.NoError(t, err)
	return service, repo
}

func TestNewService(t *testing.T) {
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()

	service, err := audit.NewService(repo, nil, logger, nil)

	require.NoError(t, err)
	assert.NotNil(t, service)
}

func TestNewService_WithConfig(t *testing.T) {
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()
	config := &audit.Config{
		RetentionPolicy: &models.AuditRetentionPolicy{
			DefaultRetentionDays: 180,
		},
	}

	service, err := audit.NewService(repo, nil, logger, config)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, 180, service.GetRetentionPolicy().DefaultRetentionDays)
}

func TestLog(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	builder := createTestBuilder(models.AuditEventIdentityAuth)
	event, err := service.Log(ctx, builder)

	assert.NoError(t, err)
	assert.NotNil(t, event)
	assert.Equal(t, int64(1), event.Sequence)
	assert.NotEmpty(t, event.EventHash)
}

func TestLogMultipleEvents_ChainIntegrity(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log first event
	builder1 := createTestBuilder(models.AuditEventIdentityAuth)
	event1, err := service.Log(ctx, builder1)
	require.NoError(t, err)

	// Log second event
	builder2 := createTestBuilder(models.AuditEventIdentityCreate)
	event2, err := service.Log(ctx, builder2)
	require.NoError(t, err)

	// Verify chain
	assert.Equal(t, int64(1), event1.Sequence)
	assert.Equal(t, int64(2), event2.Sequence)
	assert.Empty(t, event1.PrevHash) // First event has no previous hash
	assert.Equal(t, event1.EventHash, event2.PrevHash)
}

func TestQuery(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log some events
	for i := 0; i < 5; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	query := &models.AuditQuery{
		Limit: 50,
	}

	events, total, err := service.Query(ctx, query)

	assert.NoError(t, err)
	assert.Len(t, events, 5)
	assert.Equal(t, 5, total)
}

func TestQueryByEventType(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log auth events
	for i := 0; i < 3; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	// Log create events
	for i := 0; i < 2; i++ {
		builder := createTestBuilder(models.AuditEventIdentityCreate)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	query := &models.AuditQuery{
		EventTypes: []models.AuditEventType{models.AuditEventIdentityAuth},
		Limit:      50,
	}

	events, total, err := service.Query(ctx, query)

	assert.NoError(t, err)
	assert.Len(t, events, 3)
	assert.Equal(t, 3, total)
}

func TestQueryByTimeRange(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log events
	for i := 0; i < 5; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)
	query := &models.AuditQuery{
		From:  &start,
		To:    &end,
		Limit: 100,
	}

	events, total, err := service.Query(ctx, query)

	assert.NoError(t, err)
	assert.Len(t, events, 5)
	assert.Equal(t, 5, total)
}

func TestGetEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log an event
	builder := createTestBuilder(models.AuditEventIdentityAuth)
	logged, err := service.Log(ctx, builder)
	require.NoError(t, err)

	// Get it back
	event, err := service.GetEvent(ctx, logged.ID)

	assert.NoError(t, err)
	assert.NotNil(t, event)
	assert.Equal(t, logged.ID, event.ID)
}

func TestVerifyChain(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log a chain of events
	for i := 0; i < 5; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	result, err := service.VerifyChain(ctx, 1, 5)

	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 5, result.EventCount)
	assert.Equal(t, int64(1), result.FirstSequence)
	assert.Equal(t, int64(5), result.LastSequence)
}

func TestLogIdentityEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	identity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}
	actorID := uuid.New()

	err := service.LogIdentityEvent(ctx, models.AuditEventIdentityCreate, identity, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestLogCapabilityEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	capabilityID := uuid.New()
	actorID := uuid.New()

	err := service.LogCapabilityEvent(ctx, models.AuditEventCapabilityIssue, capabilityID, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestLogOperationEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	operationID := uuid.New()
	deviceID := uuid.New()
	actorID := uuid.New()

	err := service.LogOperationEvent(ctx, models.AuditEventOperationExecute, operationID, deviceID, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestLogConfigEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	deviceID := uuid.New()
	actorID := uuid.New()

	err := service.LogConfigEvent(ctx, models.AuditEventConfigDeploy, deviceID, &actorID, models.AuditResultSuccess, nil, nil)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestLogAttestationEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	deviceID := uuid.New()

	err := service.LogAttestationEvent(ctx, models.AuditEventDeviceAttest, deviceID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestLogSecurityEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	actorID := uuid.New()
	resourceID := uuid.New()

	err := service.LogSecurityEvent(ctx, models.AuditEventSecurityAlert, models.AuditSeverityCritical, &actorID, "device", &resourceID, map[string]interface{}{
		"reason": "suspicious activity",
	})

	assert.NoError(t, err)
	assert.Equal(t, int64(1), service.GetEventsLogged())
}

func TestVerifyEvent(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log an event
	builder := createTestBuilder(models.AuditEventIdentityAuth)
	logged, err := service.Log(ctx, builder)
	require.NoError(t, err)

	// Verify it
	valid, err := service.VerifyEvent(ctx, logged.ID)

	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestExport(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log some events
	for i := 0; i < 3; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	query := &models.AuditQuery{
		Limit: 50,
	}
	exportedBy := uuid.New()

	export, err := service.Export(ctx, query, exportedBy)

	assert.NoError(t, err)
	assert.NotNil(t, export)
	assert.Equal(t, 3, len(export.Events))
	assert.Equal(t, 3, export.TotalCount)
	assert.True(t, export.ChainValid)
	assert.Equal(t, exportedBy, export.ExportedBy)
}

func TestIsChainValid(t *testing.T) {
	service, _ := createService(t)

	// Initially chain should be valid
	assert.True(t, service.IsChainValid())
}

func TestGetEventsLogged(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Initially zero
	assert.Equal(t, int64(0), service.GetEventsLogged())

	// Log some events
	for i := 0; i < 5; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		_, err := service.Log(ctx, builder)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(5), service.GetEventsLogged())
}

func TestGetRetentionPolicy(t *testing.T) {
	service, _ := createService(t)

	policy := service.GetRetentionPolicy()

	assert.NotNil(t, policy)
	// Should use default policy
	assert.Equal(t, 365, policy.DefaultRetentionDays)
}

// Benchmark tests
func BenchmarkLog(b *testing.B) {
	ctx := context.Background()
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()
	service, _ := audit.NewService(repo, nil, logger, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		service.Log(ctx, builder)
	}
}

func BenchmarkQuery(b *testing.B) {
	ctx := context.Background()
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()
	service, _ := audit.NewService(repo, nil, logger, nil)

	// Pre-populate with events
	for i := 0; i < 100; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		service.Log(ctx, builder)
	}

	query := &models.AuditQuery{
		Limit: 50,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.Query(ctx, query)
	}
}

func BenchmarkVerifyChain(b *testing.B) {
	ctx := context.Background()
	logger := zap.NewNop()
	repo := audit.NewInMemoryRepository()
	service, _ := audit.NewService(repo, nil, logger, nil)

	// Pre-populate with events
	for i := 0; i < 100; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		service.Log(ctx, builder)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.VerifyChain(ctx, 1, 100)
	}
}

func TestQueryLimitCapping(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	query := &models.AuditQuery{
		Limit: 2000, // Should be capped to 1000
	}

	_, _, err := service.Query(ctx, query)
	assert.NoError(t, err)
	assert.Equal(t, 1000, query.Limit)
}

func TestQueryDefaultLimit(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	query := &models.AuditQuery{
		Limit: 0, // Should default to 50
	}

	_, _, err := service.Query(ctx, query)
	assert.NoError(t, err)
	assert.Equal(t, 50, query.Limit)
}

func TestLogIdentityEvent_WithDetails(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	identity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}
	actorID := uuid.New()
	details := map[string]interface{}{
		"username": "testuser",
		"method":   "password",
	}

	err := service.LogIdentityEvent(ctx, models.AuditEventIdentityAuth, identity, &actorID, models.AuditResultSuccess, details)

	assert.NoError(t, err)
}

func TestLogIdentityEvent_AuthFailed(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	identity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}

	err := service.LogIdentityEvent(ctx, models.AuditEventIdentityAuthFailed, identity, nil, models.AuditResultFailure, nil)

	assert.NoError(t, err)
}

func TestLogIdentityEvent_Delete(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	identity := &models.Identity{
		ID:   uuid.New(),
		Type: models.IdentityTypeOperator,
	}
	actorID := uuid.New()

	err := service.LogIdentityEvent(ctx, models.AuditEventIdentityDelete, identity, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
}

func TestLogCapabilityEvent_Revoke(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	capabilityID := uuid.New()
	actorID := uuid.New()

	err := service.LogCapabilityEvent(ctx, models.AuditEventCapabilityRevoke, capabilityID, &actorID, models.AuditResultSuccess, nil)

	assert.NoError(t, err)
}

func TestLogOperationEvent_Denied(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	operationID := uuid.New()
	deviceID := uuid.New()
	actorID := uuid.New()

	err := service.LogOperationEvent(ctx, models.AuditEventOperationDenied, operationID, deviceID, &actorID, models.AuditResultFailure, nil)

	assert.NoError(t, err)
}

func TestLogOperationEvent_Failed(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	operationID := uuid.New()
	deviceID := uuid.New()

	err := service.LogOperationEvent(ctx, models.AuditEventOperationFailed, operationID, deviceID, nil, models.AuditResultFailure, nil)

	assert.NoError(t, err)
}

func TestLogConfigEvent_Rollback(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	deviceID := uuid.New()
	actorID := uuid.New()

	err := service.LogConfigEvent(ctx, models.AuditEventConfigRollback, deviceID, &actorID, models.AuditResultSuccess, nil, nil)

	assert.NoError(t, err)
}

func TestLogAttestationEvent_Failed(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	deviceID := uuid.New()
	details := map[string]interface{}{
		"reason": "measurements mismatch",
	}

	err := service.LogAttestationEvent(ctx, models.AuditEventDeviceAttestFail, deviceID, models.AuditResultFailure, details)

	assert.NoError(t, err)
}

func TestVerifyChain_EmptyRange(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	result, err := service.VerifyChain(ctx, 1, 5)

	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.EventCount)
}

func TestVerifyEvent_MultipleEvents(t *testing.T) {
	ctx := context.Background()
	service, _ := createService(t)

	// Log multiple events
	var lastEvent *models.AuditEvent
	for i := 0; i < 3; i++ {
		builder := createTestBuilder(models.AuditEventIdentityAuth)
		event, err := service.Log(ctx, builder)
		require.NoError(t, err)
		lastEvent = event
	}

	// Verify the last event (should verify chain)
	valid, err := service.VerifyEvent(ctx, lastEvent.ID)

	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestAuditErrors(t *testing.T) {
	assert.Error(t, audit.ErrEventNotFound)
	assert.Error(t, audit.ErrChainBroken)
	assert.Error(t, audit.ErrInvalidEventHash)
	assert.Error(t, audit.ErrSequenceGap)
	assert.Error(t, audit.ErrEventAlreadyExists)

	assert.Equal(t, "audit event not found", audit.ErrEventNotFound.Error())
	assert.Equal(t, "audit chain integrity compromised", audit.ErrChainBroken.Error())
}

func TestAuditStats(t *testing.T) {
	stats := &audit.AuditStats{
		TotalEvents:       100,
		EventsByType:      map[models.AuditEventType]int64{models.AuditEventIdentityAuth: 50},
		EventsBySeverity:  map[models.AuditSeverity]int64{models.AuditSeverityInfo: 80},
		EventsByResult:    map[models.AuditResult]int64{models.AuditResultSuccess: 90},
		SecurityEvents:    5,
		FailedAuthEvents:  3,
		DeniedAccessEvents: 2,
	}

	assert.Equal(t, int64(100), stats.TotalEvents)
	assert.Equal(t, int64(50), stats.EventsByType[models.AuditEventIdentityAuth])
	assert.Equal(t, int64(5), stats.SecurityEvents)
}
