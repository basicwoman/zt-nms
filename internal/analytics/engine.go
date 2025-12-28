package analytics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

// Metric represents a single metric data point
type Metric struct {
	Name      string            `json:"name"`
	Type      MetricType        `json:"type"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
}

// DashboardStats contains statistics for the dashboard
type DashboardStats struct {
	Devices      DeviceStats      `json:"devices"`
	Identities   IdentityStats    `json:"identities"`
	Capabilities CapabilityStats  `json:"capabilities"`
	Policies     PolicyStats      `json:"policies"`
	Deployments  DeploymentStats  `json:"deployments"`
	Audit        AuditStats       `json:"audit"`
	Timestamp    time.Time        `json:"timestamp"`
}

// DeviceStats contains device statistics
type DeviceStats struct {
	Total       int `json:"total"`
	Online      int `json:"online"`
	Offline     int `json:"offline"`
	Quarantined int `json:"quarantined"`
	Unknown     int `json:"unknown"`
}

// IdentityStats contains identity statistics
type IdentityStats struct {
	Total     int `json:"total"`
	Operators int `json:"operators"`
	Devices   int `json:"devices"`
	Services  int `json:"services"`
	Active    int `json:"active"`
	Suspended int `json:"suspended"`
	Revoked   int `json:"revoked"`
}

// CapabilityStats contains capability statistics
type CapabilityStats struct {
	Active          int `json:"active"`
	PendingApproval int `json:"pending_approval"`
	ExpiredToday    int `json:"expired_today"`
	RevokedToday    int `json:"revoked_today"`
	IssuedToday     int `json:"issued_today"`
}

// PolicyStats contains policy statistics
type PolicyStats struct {
	Total            int `json:"total"`
	Active           int `json:"active"`
	EvaluationsToday int `json:"evaluations_today"`
	DenialsToday     int `json:"denials_today"`
	AllowedToday     int `json:"allowed_today"`
}

// DeploymentStats contains deployment statistics
type DeploymentStats struct {
	Pending         int `json:"pending"`
	InProgress      int `json:"in_progress"`
	CompletedToday  int `json:"completed_today"`
	FailedToday     int `json:"failed_today"`
	RolledBackToday int `json:"rolled_back_today"`
}

// AuditStats contains audit statistics
type AuditStats struct {
	EventsToday       int `json:"events_today"`
	SecurityEvents    int `json:"security_events"`
	FailedAuth        int `json:"failed_auth"`
	AccessDenials     int `json:"access_denials"`
	ConfigChanges     int `json:"config_changes"`
	AttestationEvents int `json:"attestation_events"`
}

// TimeSeriesPoint represents a single point in a time series
type TimeSeriesPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// TimeSeries represents a time series of data points
type TimeSeries struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Points []TimeSeriesPoint `json:"points"`
}

// Repository interface for analytics persistence
type Repository interface {
	SaveMetric(ctx context.Context, metric *Metric) error
	GetMetrics(ctx context.Context, name string, from, to time.Time, labels map[string]string) ([]*Metric, error)
	SaveStats(ctx context.Context, stats *DashboardStats) error
	GetLatestStats(ctx context.Context) (*DashboardStats, error)
	GetTimeSeries(ctx context.Context, name string, from, to time.Time, step time.Duration) (*TimeSeries, error)
}

// DataSource interface for collecting data
type DataSource interface {
	GetDeviceStats(ctx context.Context) (*DeviceStats, error)
	GetIdentityStats(ctx context.Context) (*IdentityStats, error)
	GetCapabilityStats(ctx context.Context) (*CapabilityStats, error)
	GetPolicyStats(ctx context.Context) (*PolicyStats, error)
	GetDeploymentStats(ctx context.Context) (*DeploymentStats, error)
	GetAuditStats(ctx context.Context, from, to time.Time) (*AuditStats, error)
}

// Engine provides analytics and metrics operations
type Engine struct {
	repo       Repository
	dataSource DataSource
	logger     *zap.Logger

	// Cache
	cachedStats *DashboardStats
	cacheTime   time.Time
	cacheTTL    time.Duration
	cacheMu     sync.RWMutex

	// Metrics collection
	metrics          map[string][]*Metric
	metricsMu        sync.RWMutex
	metricsRetention time.Duration

	// Background collection
	stopCh          chan struct{}
	collectInterval time.Duration
}

// Config contains engine configuration
type Config struct {
	CacheTTL         time.Duration
	CollectInterval  time.Duration
	MetricsRetention time.Duration
}

// NewEngine creates a new analytics engine
func NewEngine(repo Repository, dataSource DataSource, logger *zap.Logger, config *Config) *Engine {
	cacheTTL := 30 * time.Second
	collectInterval := time.Minute
	metricsRetention := 24 * time.Hour

	if config != nil {
		if config.CacheTTL > 0 {
			cacheTTL = config.CacheTTL
		}
		if config.CollectInterval > 0 {
			collectInterval = config.CollectInterval
		}
		if config.MetricsRetention > 0 {
			metricsRetention = config.MetricsRetention
		}
	}

	e := &Engine{
		repo:             repo,
		dataSource:       dataSource,
		logger:           logger,
		cacheTTL:         cacheTTL,
		metrics:          make(map[string][]*Metric),
		metricsRetention: metricsRetention,
		stopCh:           make(chan struct{}),
		collectInterval:  collectInterval,
	}

	return e
}

// Start starts background data collection
func (e *Engine) Start() {
	go e.collectLoop()
	go e.cleanupLoop()
}

// Stop stops background data collection
func (e *Engine) Stop() {
	close(e.stopCh)
}

// GetDashboardStats returns dashboard statistics
func (e *Engine) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	// Check cache
	e.cacheMu.RLock()
	if e.cachedStats != nil && time.Since(e.cacheTime) < e.cacheTTL {
		stats := e.cachedStats
		e.cacheMu.RUnlock()
		return stats, nil
	}
	e.cacheMu.RUnlock()

	// Collect fresh stats
	stats, err := e.collectStats(ctx)
	if err != nil {
		return nil, err
	}

	// Update cache
	e.cacheMu.Lock()
	e.cachedStats = stats
	e.cacheTime = time.Now()
	e.cacheMu.Unlock()

	return stats, nil
}

// collectStats collects all statistics
func (e *Engine) collectStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{
		Timestamp: time.Now().UTC(),
	}

	if e.dataSource == nil {
		return stats, nil
	}

	// Collect device stats
	if deviceStats, err := e.dataSource.GetDeviceStats(ctx); err == nil {
		stats.Devices = *deviceStats
	} else {
		e.logger.Warn("Failed to collect device stats", zap.Error(err))
	}

	// Collect identity stats
	if identityStats, err := e.dataSource.GetIdentityStats(ctx); err == nil {
		stats.Identities = *identityStats
	} else {
		e.logger.Warn("Failed to collect identity stats", zap.Error(err))
	}

	// Collect capability stats
	if capStats, err := e.dataSource.GetCapabilityStats(ctx); err == nil {
		stats.Capabilities = *capStats
	} else {
		e.logger.Warn("Failed to collect capability stats", zap.Error(err))
	}

	// Collect policy stats
	if policyStats, err := e.dataSource.GetPolicyStats(ctx); err == nil {
		stats.Policies = *policyStats
	} else {
		e.logger.Warn("Failed to collect policy stats", zap.Error(err))
	}

	// Collect deployment stats
	if deployStats, err := e.dataSource.GetDeploymentStats(ctx); err == nil {
		stats.Deployments = *deployStats
	} else {
		e.logger.Warn("Failed to collect deployment stats", zap.Error(err))
	}

	// Collect audit stats for today
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if auditStats, err := e.dataSource.GetAuditStats(ctx, startOfDay, now); err == nil {
		stats.Audit = *auditStats
	} else {
		e.logger.Warn("Failed to collect audit stats", zap.Error(err))
	}

	return stats, nil
}

// RecordMetric records a metric
func (e *Engine) RecordMetric(name string, metricType MetricType, value float64, labels map[string]string) {
	metric := &Metric{
		Name:      name,
		Type:      metricType,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now().UTC(),
	}

	e.metricsMu.Lock()
	e.metrics[name] = append(e.metrics[name], metric)
	e.metricsMu.Unlock()

	// Save to repository asynchronously
	if e.repo != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := e.repo.SaveMetric(ctx, metric); err != nil {
				e.logger.Error("Failed to save metric", zap.Error(err))
			}
		}()
	}
}

// IncrementCounter increments a counter metric
func (e *Engine) IncrementCounter(name string, labels map[string]string) {
	e.RecordMetric(name, MetricTypeCounter, 1, labels)
}

// SetGauge sets a gauge metric
func (e *Engine) SetGauge(name string, value float64, labels map[string]string) {
	e.RecordMetric(name, MetricTypeGauge, value, labels)
}

// GetTimeSeries returns a time series for a metric
func (e *Engine) GetTimeSeries(ctx context.Context, name string, from, to time.Time, step time.Duration) (*TimeSeries, error) {
	if e.repo != nil {
		return e.repo.GetTimeSeries(ctx, name, from, to, step)
	}

	// Fall back to in-memory metrics
	e.metricsMu.RLock()
	defer e.metricsMu.RUnlock()

	metrics, exists := e.metrics[name]
	if !exists {
		return &TimeSeries{Name: name, Points: []TimeSeriesPoint{}}, nil
	}

	points := make([]TimeSeriesPoint, 0)
	for _, m := range metrics {
		if m.Timestamp.After(from) && m.Timestamp.Before(to) {
			points = append(points, TimeSeriesPoint{
				Timestamp: m.Timestamp,
				Value:     m.Value,
				Labels:    m.Labels,
			})
		}
	}

	return &TimeSeries{Name: name, Points: points}, nil
}

// GetPolicyEvaluationTrend returns policy evaluation trend over time
func (e *Engine) GetPolicyEvaluationTrend(ctx context.Context, hours int) ([]map[string]interface{}, error) {
	now := time.Now()
	trend := make([]map[string]interface{}, 0, hours)

	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		hour := t.Format("15:00")

		// In production, query actual data
		trend = append(trend, map[string]interface{}{
			"time":    hour,
			"allowed": 0,
			"denied":  0,
		})
	}

	return trend, nil
}

// GetDeviceStatusDistribution returns device status distribution
func (e *Engine) GetDeviceStatusDistribution(ctx context.Context) ([]map[string]interface{}, error) {
	stats, err := e.GetDashboardStats(ctx)
	if err != nil {
		return nil, err
	}

	return []map[string]interface{}{
		{"name": "Online", "value": stats.Devices.Online, "color": "#22c55e"},
		{"name": "Offline", "value": stats.Devices.Offline, "color": "#ef4444"},
		{"name": "Quarantined", "value": stats.Devices.Quarantined, "color": "#f59e0b"},
		{"name": "Unknown", "value": stats.Devices.Unknown, "color": "#6b7280"},
	}, nil
}

// GetConfigDeploymentTrend returns configuration deployment trend
func (e *Engine) GetConfigDeploymentTrend(ctx context.Context, days int) ([]map[string]interface{}, error) {
	now := time.Now()
	trend := make([]map[string]interface{}, 0, days)
	dayNames := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

	for i := days - 1; i >= 0; i-- {
		t := now.AddDate(0, 0, -i)
		dayName := dayNames[t.Weekday()]

		// In production, query actual data
		trend = append(trend, map[string]interface{}{
			"day":     dayName,
			"success": 0,
			"failed":  0,
		})
	}

	return trend, nil
}

// GetRecentEvents returns recent audit events
func (e *Engine) GetRecentEvents(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	// In production, query from audit service
	return []map[string]interface{}{}, nil
}

// GetTopDevicesByOperations returns top devices by operation count
func (e *Engine) GetTopDevicesByOperations(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// GetTopOperatorsByActivity returns top operators by activity
func (e *Engine) GetTopOperatorsByActivity(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// GetSecurityTrend returns security event trend
func (e *Engine) GetSecurityTrend(ctx context.Context, days int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// RecordPolicyEvaluation records a policy evaluation
func (e *Engine) RecordPolicyEvaluation(decision models.PolicyEffect, policyID uuid.UUID, duration time.Duration) {
	labels := map[string]string{
		"decision":  string(decision),
		"policy_id": policyID.String(),
	}
	e.IncrementCounter("ztnms_policy_evaluations_total", labels)
	e.RecordMetric("ztnms_policy_evaluation_duration_ms", MetricTypeHistogram, float64(duration.Milliseconds()), labels)
}

// RecordAuthentication records an authentication attempt
func (e *Engine) RecordAuthentication(success bool, identityType models.IdentityType) {
	labels := map[string]string{
		"success":       fmt.Sprintf("%t", success),
		"identity_type": string(identityType),
	}
	e.IncrementCounter("ztnms_authentications_total", labels)
}

// RecordOperation records a device operation
func (e *Engine) RecordOperation(operationType string, deviceID uuid.UUID, success bool, duration time.Duration) {
	labels := map[string]string{
		"operation": operationType,
		"device_id": deviceID.String(),
		"success":   fmt.Sprintf("%t", success),
	}
	e.IncrementCounter("ztnms_operations_total", labels)
	e.RecordMetric("ztnms_operation_duration_ms", MetricTypeHistogram, float64(duration.Milliseconds()), labels)
}

// RecordAttestation records an attestation result
func (e *Engine) RecordAttestation(status models.AttestationStatus, deviceID uuid.UUID) {
	labels := map[string]string{
		"status":    string(status),
		"device_id": deviceID.String(),
	}
	e.IncrementCounter("ztnms_attestations_total", labels)
}

// RecordConfigDeployment records a configuration deployment
func (e *Engine) RecordConfigDeployment(status string, deviceID uuid.UUID, duration time.Duration) {
	labels := map[string]string{
		"status":    status,
		"device_id": deviceID.String(),
	}
	e.IncrementCounter("ztnms_config_deployments_total", labels)
	e.RecordMetric("ztnms_config_deployment_duration_ms", MetricTypeHistogram, float64(duration.Milliseconds()), labels)
}

// collectLoop periodically collects statistics
func (e *Engine) collectLoop() {
	ticker := time.NewTicker(e.collectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			stats, err := e.collectStats(ctx)
			if err != nil {
				e.logger.Error("Failed to collect stats", zap.Error(err))
			} else {
				e.cacheMu.Lock()
				e.cachedStats = stats
				e.cacheTime = time.Now()
				e.cacheMu.Unlock()

				// Save to repository
				if e.repo != nil {
					if err := e.repo.SaveStats(ctx, stats); err != nil {
						e.logger.Error("Failed to save stats", zap.Error(err))
					}
				}
			}
			cancel()
		}
	}
}

// cleanupLoop periodically cleans up old metrics
func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.cleanupOldMetrics()
		}
	}
}

// cleanupOldMetrics removes metrics older than retention period
func (e *Engine) cleanupOldMetrics() {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	cutoff := time.Now().Add(-e.metricsRetention)
	for name, metrics := range e.metrics {
		filtered := make([]*Metric, 0)
		for _, m := range metrics {
			if m.Timestamp.After(cutoff) {
				filtered = append(filtered, m)
			}
		}
		e.metrics[name] = filtered
	}
}
