package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDataSource implements DataSource using PostgreSQL
type PostgresDataSource struct {
	pool *pgxpool.Pool
}

// NewPostgresDataSource creates a new PostgreSQL data source
func NewPostgresDataSource(pool *pgxpool.Pool) *PostgresDataSource {
	return &PostgresDataSource{pool: pool}
}

// GetDeviceStats returns device statistics from the database
func (ds *PostgresDataSource) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	stats := &DeviceStats{}
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'online') as online,
			COUNT(*) FILTER (WHERE status = 'offline') as offline,
			COUNT(*) FILTER (WHERE status = 'quarantined' OR trust_status = 'quarantined') as quarantined,
			COUNT(*) FILTER (WHERE status = 'unknown' OR status = 'degraded') as unknown
		FROM devices
	`
	err := ds.pool.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Online,
		&stats.Offline,
		&stats.Quarantined,
		&stats.Unknown,
	)
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// GetIdentityStats returns identity statistics from the database
func (ds *PostgresDataSource) GetIdentityStats(ctx context.Context) (*IdentityStats, error) {
	stats := &IdentityStats{}
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE type = 'operator') as operators,
			COUNT(*) FILTER (WHERE type = 'device') as devices,
			COUNT(*) FILTER (WHERE type = 'service') as services,
			COUNT(*) FILTER (WHERE status = 'active') as active,
			COUNT(*) FILTER (WHERE status = 'suspended') as suspended,
			COUNT(*) FILTER (WHERE status = 'revoked') as revoked
		FROM identities
	`
	err := ds.pool.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Operators,
		&stats.Devices,
		&stats.Services,
		&stats.Active,
		&stats.Suspended,
		&stats.Revoked,
	)
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// GetCapabilityStats returns capability statistics from the database
func (ds *PostgresDataSource) GetCapabilityStats(ctx context.Context) (*CapabilityStats, error) {
	stats := &CapabilityStats{}
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	query := `
		SELECT
			COUNT(*) FILTER (WHERE revoked = FALSE AND (validity->>'not_after')::timestamptz > NOW()) as active,
			0 as pending_approval,
			COUNT(*) FILTER (WHERE (validity->>'not_after')::timestamptz BETWEEN $1 AND $2) as expired_today,
			COUNT(*) FILTER (WHERE revoked = TRUE AND updated_at BETWEEN $1 AND $2) as revoked_today,
			COUNT(*) FILTER (WHERE created_at BETWEEN $1 AND $2) as issued_today
		FROM capabilities
	`
	err := ds.pool.QueryRow(ctx, query, startOfDay, endOfDay).Scan(
		&stats.Active,
		&stats.PendingApproval,
		&stats.ExpiredToday,
		&stats.RevokedToday,
		&stats.IssuedToday,
	)
	if err != nil {
		// Return empty stats if table doesn't exist or query fails
		return &CapabilityStats{}, nil
	}
	return stats, nil
}

// GetPolicyStats returns policy statistics from the database
func (ds *PostgresDataSource) GetPolicyStats(ctx context.Context) (*PolicyStats, error) {
	stats := &PolicyStats{}
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'active') as active
		FROM policies
	`
	err := ds.pool.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Active,
	)
	if err != nil {
		return nil, err
	}
	// Evaluations would come from audit events or a separate metrics table
	stats.EvaluationsToday = 0
	stats.DenialsToday = 0
	stats.AllowedToday = 0
	return stats, nil
}

// GetDeploymentStats returns deployment statistics from the database
func (ds *PostgresDataSource) GetDeploymentStats(ctx context.Context) (*DeploymentStats, error) {
	stats := &DeploymentStats{}
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	query := `
		SELECT
			COUNT(*) FILTER (WHERE deployment_status = 'pending') as pending,
			COUNT(*) FILTER (WHERE deployment_status = 'in_progress') as in_progress,
			COUNT(*) FILTER (WHERE deployment_status = 'applied' AND applied_at >= $1) as completed_today,
			COUNT(*) FILTER (WHERE deployment_status = 'failed' AND created_at >= $1) as failed_today,
			COUNT(*) FILTER (WHERE deployment_status = 'rolled_back' AND created_at >= $1) as rolled_back_today
		FROM config_blocks
	`
	err := ds.pool.QueryRow(ctx, query, startOfDay).Scan(
		&stats.Pending,
		&stats.InProgress,
		&stats.CompletedToday,
		&stats.FailedToday,
		&stats.RolledBackToday,
	)
	if err != nil {
		// Return empty stats if table doesn't exist or query fails
		return &DeploymentStats{}, nil
	}
	return stats, nil
}

// GetAuditStats returns audit statistics for a time range
func (ds *PostgresDataSource) GetAuditStats(ctx context.Context, from, to time.Time) (*AuditStats, error) {
	stats := &AuditStats{}
	query := `
		SELECT
			COUNT(*) as events_today,
			COUNT(*) FILTER (WHERE severity IN ('warning', 'critical')) as security_events,
			COUNT(*) FILTER (WHERE event_type LIKE '%auth%' AND result = 'failure') as failed_auth,
			COUNT(*) FILTER (WHERE event_type LIKE '%access%' AND result = 'denied') as access_denials,
			COUNT(*) FILTER (WHERE event_type LIKE '%config%') as config_changes,
			COUNT(*) FILTER (WHERE event_type LIKE '%attest%') as attestation_events
		FROM audit_events
		WHERE timestamp BETWEEN $1 AND $2
	`
	err := ds.pool.QueryRow(ctx, query, from, to).Scan(
		&stats.EventsToday,
		&stats.SecurityEvents,
		&stats.FailedAuth,
		&stats.AccessDenials,
		&stats.ConfigChanges,
		&stats.AttestationEvents,
	)
	if err != nil {
		// Return empty stats if table doesn't exist or query fails
		return &AuditStats{}, nil
	}
	return stats, nil
}
