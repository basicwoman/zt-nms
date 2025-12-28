package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// Append appends an audit event (append-only)
func (r *PostgresRepository) Append(ctx context.Context, event *models.AuditEvent) error {
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO audit_events (
			id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			action, result, details, capability_id, operation_id, session_id,
			operation_signature, source_ip::text, user_agent, request_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22, $23
		)
	`

	_, err = r.pool.Exec(ctx, query,
		event.ID,
		event.Sequence,
		event.PrevHash,
		event.EventHash,
		event.Timestamp,
		event.EventType,
		event.Severity,
		event.ActorID,
		event.ActorType,
		event.ActorName,
		event.ResourceType,
		event.ResourceID,
		event.ResourceName,
		event.Action,
		event.Result,
		detailsJSON,
		event.CapabilityID,
		event.OperationID,
		event.SessionID,
		event.OperationSignature,
		event.SourceIP,
		event.UserAgent,
		event.RequestID,
	)
	return err
}

// GetByID retrieves an audit event by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditEvent, error) {
	query := `
		SELECT id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			   actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			   action, result, details, capability_id, operation_id, session_id,
			   operation_signature, source_ip::text, user_agent, request_id
		FROM audit_events
		WHERE id = $1
	`
	return r.scanEvent(r.pool.QueryRow(ctx, query, id))
}

// GetBySequence retrieves an audit event by sequence number
func (r *PostgresRepository) GetBySequence(ctx context.Context, sequence int64) (*models.AuditEvent, error) {
	query := `
		SELECT id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			   actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			   action, result, details, capability_id, operation_id, session_id,
			   operation_signature, source_ip::text, user_agent, request_id
		FROM audit_events
		WHERE sequence = $1
	`
	return r.scanEvent(r.pool.QueryRow(ctx, query, sequence))
}

// GetLastEvent retrieves the most recent audit event
func (r *PostgresRepository) GetLastEvent(ctx context.Context) (*models.AuditEvent, error) {
	query := `
		SELECT id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			   actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			   action, result, details, capability_id, operation_id, session_id,
			   operation_signature, source_ip::text, user_agent, request_id
		FROM audit_events
		ORDER BY sequence DESC
		LIMIT 1
	`
	return r.scanEvent(r.pool.QueryRow(ctx, query))
}

// Query queries audit events with filters
func (r *PostgresRepository) Query(ctx context.Context, query *models.AuditQuery) ([]*models.AuditEvent, int, error) {
	conditions := []string{}
	args := []interface{}{}
	argIndex := 1

	if query.From != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, *query.From)
		argIndex++
	}

	if query.To != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIndex))
		args = append(args, *query.To)
		argIndex++
	}

	if len(query.EventTypes) > 0 {
		placeholders := make([]string, len(query.EventTypes))
		for i, et := range query.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, et)
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(query.Severities) > 0 {
		placeholders := make([]string, len(query.Severities))
		for i, s := range query.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s)
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	if query.ActorID != nil {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", argIndex))
		args = append(args, *query.ActorID)
		argIndex++
	}

	if query.ActorType != "" {
		conditions = append(conditions, fmt.Sprintf("actor_type = $%d", argIndex))
		args = append(args, query.ActorType)
		argIndex++
	}

	if query.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIndex))
		args = append(args, query.ResourceType)
		argIndex++
	}

	if query.ResourceID != nil {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIndex))
		args = append(args, *query.ResourceID)
		argIndex++
	}

	if query.Result != "" {
		conditions = append(conditions, fmt.Sprintf("result = $%d", argIndex))
		args = append(args, query.Result)
		argIndex++
	}

	if query.CapabilityID != nil {
		conditions = append(conditions, fmt.Sprintf("capability_id = $%d", argIndex))
		args = append(args, *query.CapabilityID)
		argIndex++
	}

	if query.SourceIP != "" {
		conditions = append(conditions, fmt.Sprintf("source_ip = $%d", argIndex))
		args = append(args, query.SourceIP)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_events %s", whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	orderBy := "sequence DESC"
	if query.OrderBy != "" {
		orderBy = query.OrderBy
		if query.Order == "asc" {
			orderBy += " ASC"
		} else {
			orderBy += " DESC"
		}
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			   actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			   action, result, details, capability_id, operation_id, session_id,
			   operation_signature, source_ip::text, user_agent, request_id
		FROM audit_events
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, query.Limit, query.Offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	events := make([]*models.AuditEvent, 0)
	for rows.Next() {
		event, err := r.scanEventFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}

	return events, total, rows.Err()
}

// GetEventRange retrieves events in a sequence range
func (r *PostgresRepository) GetEventRange(ctx context.Context, fromSeq, toSeq int64) ([]*models.AuditEvent, error) {
	query := `
		SELECT id, sequence, prev_hash, event_hash, timestamp, event_type, severity,
			   actor_id, actor_type, actor_name, resource_type, resource_id, resource_name,
			   action, result, details, capability_id, operation_id, session_id,
			   operation_signature, source_ip::text, user_agent, request_id
		FROM audit_events
		WHERE sequence >= $1 AND sequence <= $2
		ORDER BY sequence ASC
	`

	rows, err := r.pool.Query(ctx, query, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]*models.AuditEvent, 0)
	for rows.Next() {
		event, err := r.scanEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

// GetStats retrieves audit statistics
func (r *PostgresRepository) GetStats(ctx context.Context, from, to time.Time) (*AuditStats, error) {
	stats := &AuditStats{
		EventsByType:     make(map[models.AuditEventType]int64),
		EventsBySeverity: make(map[models.AuditSeverity]int64),
		EventsByResult:   make(map[models.AuditResult]int64),
	}

	// Total count
	countQuery := `SELECT COUNT(*) FROM audit_events WHERE timestamp >= $1 AND timestamp <= $2`
	if err := r.pool.QueryRow(ctx, countQuery, from, to).Scan(&stats.TotalEvents); err != nil {
		return nil, err
	}

	// By type
	typeQuery := `
		SELECT event_type, COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		GROUP BY event_type
	`
	rows, err := r.pool.Query(ctx, typeQuery, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var eventType models.AuditEventType
		var count int64
		if err := rows.Scan(&eventType, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.EventsByType[eventType] = count
	}
	rows.Close()

	// By severity
	severityQuery := `
		SELECT severity, COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		GROUP BY severity
	`
	rows, err = r.pool.Query(ctx, severityQuery, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var severity models.AuditSeverity
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.EventsBySeverity[severity] = count
	}
	rows.Close()

	// By result
	resultQuery := `
		SELECT result, COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		GROUP BY result
	`
	rows, err = r.pool.Query(ctx, resultQuery, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var result models.AuditResult
		var count int64
		if err := rows.Scan(&result, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.EventsByResult[result] = count
	}
	rows.Close()

	// Security events
	securityQuery := `
		SELECT COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		AND event_type IN ('security.alert', 'security.incident', 'security.violation')
	`
	if err := r.pool.QueryRow(ctx, securityQuery, from, to).Scan(&stats.SecurityEvents); err != nil {
		return nil, err
	}

	// Failed auth
	authQuery := `
		SELECT COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		AND event_type = 'identity.auth_failed'
	`
	if err := r.pool.QueryRow(ctx, authQuery, from, to).Scan(&stats.FailedAuthEvents); err != nil {
		return nil, err
	}

	// Denied access
	deniedQuery := `
		SELECT COUNT(*)
		FROM audit_events
		WHERE timestamp >= $1 AND timestamp <= $2
		AND event_type = 'operation.denied'
	`
	if err := r.pool.QueryRow(ctx, deniedQuery, from, to).Scan(&stats.DeniedAccessEvents); err != nil {
		return nil, err
	}

	return stats, nil
}

func (r *PostgresRepository) scanEvent(row pgx.Row) (*models.AuditEvent, error) {
	var event models.AuditEvent
	var detailsJSON []byte
	var actorType, actorName, resourceType, resourceName, action, result, sourceIP, userAgent, requestID *string

	err := row.Scan(
		&event.ID,
		&event.Sequence,
		&event.PrevHash,
		&event.EventHash,
		&event.Timestamp,
		&event.EventType,
		&event.Severity,
		&event.ActorID,
		&actorType,
		&actorName,
		&resourceType,
		&event.ResourceID,
		&resourceName,
		&action,
		&result,
		&detailsJSON,
		&event.CapabilityID,
		&event.OperationID,
		&event.SessionID,
		&event.OperationSignature,
		&sourceIP,
		&userAgent,
		&requestID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEventNotFound
		}
		return nil, err
	}

	// Handle nullable string fields
	if actorType != nil {
		event.ActorType = models.IdentityType(*actorType)
	}
	if actorName != nil {
		event.ActorName = *actorName
	}
	if resourceType != nil {
		event.ResourceType = *resourceType
	}
	if resourceName != nil {
		event.ResourceName = *resourceName
	}
	if action != nil {
		event.Action = *action
	}
	if result != nil {
		event.Result = models.AuditResult(*result)
	}
	if sourceIP != nil {
		event.SourceIP = *sourceIP
	}
	if userAgent != nil {
		event.UserAgent = *userAgent
	}
	if requestID != nil {
		event.RequestID = *requestID
	}

	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
			return nil, err
		}
	}

	return &event, nil
}

func (r *PostgresRepository) scanEventFromRows(rows pgx.Rows) (*models.AuditEvent, error) {
	var event models.AuditEvent
	var detailsJSON []byte
	var actorType, actorName, resourceType, resourceName, action, result, sourceIP, userAgent, requestID *string

	err := rows.Scan(
		&event.ID,
		&event.Sequence,
		&event.PrevHash,
		&event.EventHash,
		&event.Timestamp,
		&event.EventType,
		&event.Severity,
		&event.ActorID,
		&actorType,
		&actorName,
		&resourceType,
		&event.ResourceID,
		&resourceName,
		&action,
		&result,
		&detailsJSON,
		&event.CapabilityID,
		&event.OperationID,
		&event.SessionID,
		&event.OperationSignature,
		&sourceIP,
		&userAgent,
		&requestID,
	)
	if err != nil {
		return nil, err
	}

	// Handle nullable string fields
	if actorType != nil {
		event.ActorType = models.IdentityType(*actorType)
	}
	if actorName != nil {
		event.ActorName = *actorName
	}
	if resourceType != nil {
		event.ResourceType = *resourceType
	}
	if resourceName != nil {
		event.ResourceName = *resourceName
	}
	if action != nil {
		event.Action = *action
	}
	if result != nil {
		event.Result = models.AuditResult(*result)
	}
	if sourceIP != nil {
		event.SourceIP = *sourceIP
	}
	if userAgent != nil {
		event.UserAgent = *userAgent
	}
	if requestID != nil {
		event.RequestID = *requestID
	}

	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &event.Details); err != nil {
			return nil, err
		}
	}

	return &event, nil
}

// InMemoryRepository implements Repository using in-memory storage
type InMemoryRepository struct {
	events     []*models.AuditEvent
	byID       map[uuid.UUID]*models.AuditEvent
	bySequence map[int64]*models.AuditEvent
	mu         sync.RWMutex
}

// NewInMemoryRepository creates a new in-memory repository
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		events:     make([]*models.AuditEvent, 0),
		byID:       make(map[uuid.UUID]*models.AuditEvent),
		bySequence: make(map[int64]*models.AuditEvent),
	}
}

// Append appends an audit event (in-memory)
func (r *InMemoryRepository) Append(ctx context.Context, event *models.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byID[event.ID]; exists {
		return ErrEventAlreadyExists
	}

	r.events = append(r.events, event)
	r.byID[event.ID] = event
	r.bySequence[event.Sequence] = event
	return nil
}

// GetByID retrieves an event by ID (in-memory)
func (r *InMemoryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	event, exists := r.byID[id]
	if !exists {
		return nil, ErrEventNotFound
	}
	return event, nil
}

// GetBySequence retrieves an event by sequence (in-memory)
func (r *InMemoryRepository) GetBySequence(ctx context.Context, sequence int64) (*models.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	event, exists := r.bySequence[sequence]
	if !exists {
		return nil, ErrEventNotFound
	}
	return event, nil
}

// GetLastEvent retrieves the last event (in-memory)
func (r *InMemoryRepository) GetLastEvent(ctx context.Context) (*models.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.events) == 0 {
		return nil, ErrEventNotFound
	}
	return r.events[len(r.events)-1], nil
}

// Query queries events (in-memory)
func (r *InMemoryRepository) Query(ctx context.Context, query *models.AuditQuery) ([]*models.AuditEvent, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := make([]*models.AuditEvent, 0)
	for _, event := range r.events {
		if r.matchesQuery(event, query) {
			filtered = append(filtered, event)
		}
	}

	total := len(filtered)

	// Apply offset and limit
	start := int(query.Offset)
	if start >= len(filtered) {
		return []*models.AuditEvent{}, total, nil
	}

	end := start + query.Limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[start:end], total, nil
}

// GetEventRange retrieves events in a range (in-memory)
func (r *InMemoryRepository) GetEventRange(ctx context.Context, fromSeq, toSeq int64) ([]*models.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*models.AuditEvent, 0)
	for seq := fromSeq; seq <= toSeq; seq++ {
		if event, exists := r.bySequence[seq]; exists {
			result = append(result, event)
		}
	}
	return result, nil
}

// GetStats retrieves stats (in-memory)
func (r *InMemoryRepository) GetStats(ctx context.Context, from, to time.Time) (*AuditStats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := &AuditStats{
		EventsByType:     make(map[models.AuditEventType]int64),
		EventsBySeverity: make(map[models.AuditSeverity]int64),
		EventsByResult:   make(map[models.AuditResult]int64),
	}

	for _, event := range r.events {
		if event.Timestamp.Before(from) || event.Timestamp.After(to) {
			continue
		}

		stats.TotalEvents++
		stats.EventsByType[event.EventType]++
		stats.EventsBySeverity[event.Severity]++
		stats.EventsByResult[event.Result]++

		switch event.EventType {
		case models.AuditEventSecurityAlert, models.AuditEventSecurityIncident, models.AuditEventSecurityViolation:
			stats.SecurityEvents++
		case models.AuditEventIdentityAuthFailed:
			stats.FailedAuthEvents++
		case models.AuditEventOperationDenied:
			stats.DeniedAccessEvents++
		}
	}

	return stats, nil
}

func (r *InMemoryRepository) matchesQuery(event *models.AuditEvent, query *models.AuditQuery) bool {
	if query.From != nil && event.Timestamp.Before(*query.From) {
		return false
	}
	if query.To != nil && event.Timestamp.After(*query.To) {
		return false
	}
	if len(query.EventTypes) > 0 {
		found := false
		for _, et := range query.EventTypes {
			if event.EventType == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(query.Severities) > 0 {
		found := false
		for _, s := range query.Severities {
			if event.Severity == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if query.ActorID != nil && (event.ActorID == nil || *event.ActorID != *query.ActorID) {
		return false
	}
	if query.ActorType != "" && event.ActorType != query.ActorType {
		return false
	}
	if query.ResourceType != "" && event.ResourceType != query.ResourceType {
		return false
	}
	if query.ResourceID != nil && (event.ResourceID == nil || *event.ResourceID != *query.ResourceID) {
		return false
	}
	if query.Result != "" && event.Result != query.Result {
		return false
	}
	return true
}
