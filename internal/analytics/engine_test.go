package analytics

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

// MockRepository is a mock implementation of Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) SaveMetric(ctx context.Context, metric *Metric) error {
	args := m.Called(ctx, metric)
	return args.Error(0)
}

func (m *MockRepository) GetMetrics(ctx context.Context, name string, from, to time.Time, labels map[string]string) ([]*Metric, error) {
	args := m.Called(ctx, name, from, to, labels)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Metric), args.Error(1)
}

func (m *MockRepository) SaveStats(ctx context.Context, stats *DashboardStats) error {
	args := m.Called(ctx, stats)
	return args.Error(0)
}

func (m *MockRepository) GetLatestStats(ctx context.Context) (*DashboardStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DashboardStats), args.Error(1)
}

func (m *MockRepository) GetTimeSeries(ctx context.Context, name string, from, to time.Time, step time.Duration) (*TimeSeries, error) {
	args := m.Called(ctx, name, from, to, step)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TimeSeries), args.Error(1)
}

// MockDataSource is a mock implementation of DataSource
type MockDataSource struct {
	mock.Mock
}

func (m *MockDataSource) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeviceStats), args.Error(1)
}

func (m *MockDataSource) GetIdentityStats(ctx context.Context) (*IdentityStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*IdentityStats), args.Error(1)
}

func (m *MockDataSource) GetCapabilityStats(ctx context.Context) (*CapabilityStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*CapabilityStats), args.Error(1)
}

func (m *MockDataSource) GetPolicyStats(ctx context.Context) (*PolicyStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PolicyStats), args.Error(1)
}

func (m *MockDataSource) GetDeploymentStats(ctx context.Context) (*DeploymentStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeploymentStats), args.Error(1)
}

func (m *MockDataSource) GetAuditStats(ctx context.Context, from, to time.Time) (*AuditStats, error) {
	args := m.Called(ctx, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuditStats), args.Error(1)
}

func TestMetricTypes(t *testing.T) {
	types := []MetricType{
		MetricTypeCounter,
		MetricTypeGauge,
		MetricTypeHistogram,
	}

	for _, mt := range types {
		assert.NotEmpty(t, string(mt))
	}
}

func TestMetric(t *testing.T) {
	metric := Metric{
		Name:  "cpu_usage",
		Type:  MetricTypeGauge,
		Value: 75.5,
		Labels: map[string]string{
			"device": "router-01",
			"region": "us-east",
		},
		Timestamp: time.Now(),
	}

	assert.Equal(t, "cpu_usage", metric.Name)
	assert.Equal(t, MetricTypeGauge, metric.Type)
	assert.Equal(t, 75.5, metric.Value)
	assert.Equal(t, "router-01", metric.Labels["device"])
}

func TestDashboardStats(t *testing.T) {
	stats := DashboardStats{
		Devices: DeviceStats{
			Total:       100,
			Online:      80,
			Offline:     15,
			Quarantined: 3,
			Unknown:     2,
		},
		Identities: IdentityStats{
			Total:     50,
			Operators: 20,
			Devices:   25,
			Services:  5,
			Active:    45,
			Suspended: 3,
			Revoked:   2,
		},
		Capabilities: CapabilityStats{
			Active:          100,
			PendingApproval: 5,
			ExpiredToday:    10,
			RevokedToday:    2,
			IssuedToday:     15,
		},
		Policies: PolicyStats{
			Total:            10,
			Active:           8,
			EvaluationsToday: 1000,
			DenialsToday:     50,
			AllowedToday:     950,
		},
		Deployments: DeploymentStats{
			Pending:         3,
			InProgress:      2,
			CompletedToday:  10,
			FailedToday:     1,
			RolledBackToday: 0,
		},
		Audit: AuditStats{
			EventsToday:       5000,
			SecurityEvents:    100,
			FailedAuth:        25,
			AccessDenials:     50,
			ConfigChanges:     200,
			AttestationEvents: 50,
		},
		Timestamp: time.Now(),
	}

	assert.Equal(t, 100, stats.Devices.Total)
	assert.Equal(t, 80, stats.Devices.Online)
	assert.Equal(t, 50, stats.Identities.Total)
	assert.Equal(t, 100, stats.Capabilities.Active)
	assert.Equal(t, 10, stats.Policies.Total)
	assert.Equal(t, 5000, stats.Audit.EventsToday)
}

func TestDeviceStats(t *testing.T) {
	stats := DeviceStats{
		Total:       100,
		Online:      80,
		Offline:     10,
		Quarantined: 5,
		Unknown:     5,
	}

	assert.Equal(t, 100, stats.Total)
	assert.Equal(t, stats.Online+stats.Offline+stats.Quarantined+stats.Unknown, stats.Total)
}

func TestIdentityStats(t *testing.T) {
	stats := IdentityStats{
		Total:     50,
		Operators: 20,
		Devices:   25,
		Services:  5,
		Active:    45,
		Suspended: 3,
		Revoked:   2,
	}

	assert.Equal(t, 50, stats.Total)
	assert.Equal(t, stats.Operators+stats.Devices+stats.Services, stats.Total)
	assert.Equal(t, stats.Active+stats.Suspended+stats.Revoked, stats.Total)
}

func TestCapabilityStats(t *testing.T) {
	stats := CapabilityStats{
		Active:          100,
		PendingApproval: 5,
		ExpiredToday:    10,
		RevokedToday:    2,
		IssuedToday:     15,
	}

	assert.Equal(t, 100, stats.Active)
	assert.Equal(t, 15, stats.IssuedToday)
}

func TestPolicyStats(t *testing.T) {
	stats := PolicyStats{
		Total:            10,
		Active:           8,
		EvaluationsToday: 1000,
		DenialsToday:     50,
		AllowedToday:     950,
	}

	assert.Equal(t, 10, stats.Total)
	assert.Equal(t, stats.DenialsToday+stats.AllowedToday, stats.EvaluationsToday)
}

func TestDeploymentStats(t *testing.T) {
	stats := DeploymentStats{
		Pending:         3,
		InProgress:      2,
		CompletedToday:  10,
		FailedToday:     1,
		RolledBackToday: 0,
	}

	assert.Equal(t, 3, stats.Pending)
	assert.Equal(t, 2, stats.InProgress)
}

func TestAuditStats(t *testing.T) {
	stats := AuditStats{
		EventsToday:       5000,
		SecurityEvents:    100,
		FailedAuth:        25,
		AccessDenials:     50,
		ConfigChanges:     200,
		AttestationEvents: 50,
	}

	assert.Equal(t, 5000, stats.EventsToday)
	assert.Equal(t, 100, stats.SecurityEvents)
}

// ========== Engine Tests ==========

func TestNewEngine(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	assert.NotNil(t, engine)
	assert.Equal(t, 30*time.Second, engine.cacheTTL)
	assert.Equal(t, time.Minute, engine.collectInterval)
	assert.Equal(t, 24*time.Hour, engine.metricsRetention)
}

func TestNewEngine_WithConfig(t *testing.T) {
	logger := zap.NewNop()
	config := &Config{
		CacheTTL:         time.Minute,
		CollectInterval:  5 * time.Minute,
		MetricsRetention: 48 * time.Hour,
	}
	engine := NewEngine(nil, nil, logger, config)

	assert.NotNil(t, engine)
	assert.Equal(t, time.Minute, engine.cacheTTL)
	assert.Equal(t, 5*time.Minute, engine.collectInterval)
	assert.Equal(t, 48*time.Hour, engine.metricsRetention)
}

func TestEngine_GetDashboardStats_WithMockDataSource(t *testing.T) {
	logger := zap.NewNop()
	mockDS := new(MockDataSource)

	// Setup expectations
	mockDS.On("GetDeviceStats", mock.Anything).Return(&DeviceStats{
		Total:  10,
		Online: 8,
	}, nil)
	mockDS.On("GetIdentityStats", mock.Anything).Return(&IdentityStats{
		Total:     5,
		Operators: 3,
	}, nil)
	mockDS.On("GetCapabilityStats", mock.Anything).Return(&CapabilityStats{
		Active: 20,
	}, nil)
	mockDS.On("GetPolicyStats", mock.Anything).Return(&PolicyStats{
		Total:  10,
		Active: 8,
	}, nil)
	mockDS.On("GetDeploymentStats", mock.Anything).Return(&DeploymentStats{
		Pending: 2,
	}, nil)
	mockDS.On("GetAuditStats", mock.Anything, mock.Anything, mock.Anything).Return(&AuditStats{
		EventsToday: 100,
	}, nil)

	engine := NewEngine(nil, mockDS, logger, nil)
	stats, err := engine.GetDashboardStats(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, 10, stats.Devices.Total)
	assert.Equal(t, 8, stats.Devices.Online)
	assert.Equal(t, 5, stats.Identities.Total)
	assert.Equal(t, 20, stats.Capabilities.Active)
	assert.Equal(t, 10, stats.Policies.Total)
	assert.Equal(t, 2, stats.Deployments.Pending)
	assert.Equal(t, 100, stats.Audit.EventsToday)

	mockDS.AssertExpectations(t)
}

func TestEngine_GetDashboardStats_UsesCache(t *testing.T) {
	logger := zap.NewNop()
	mockDS := new(MockDataSource)

	mockDS.On("GetDeviceStats", mock.Anything).Return(&DeviceStats{Total: 10}, nil).Once()
	mockDS.On("GetIdentityStats", mock.Anything).Return(&IdentityStats{Total: 5}, nil).Once()
	mockDS.On("GetCapabilityStats", mock.Anything).Return(&CapabilityStats{Active: 20}, nil).Once()
	mockDS.On("GetPolicyStats", mock.Anything).Return(&PolicyStats{Total: 10}, nil).Once()
	mockDS.On("GetDeploymentStats", mock.Anything).Return(&DeploymentStats{Pending: 2}, nil).Once()
	mockDS.On("GetAuditStats", mock.Anything, mock.Anything, mock.Anything).Return(&AuditStats{EventsToday: 100}, nil).Once()

	engine := NewEngine(nil, mockDS, logger, &Config{CacheTTL: time.Minute})

	// First call
	stats1, err1 := engine.GetDashboardStats(context.Background())
	assert.NoError(t, err1)
	assert.Equal(t, 10, stats1.Devices.Total)

	// Second call should use cache
	stats2, err2 := engine.GetDashboardStats(context.Background())
	assert.NoError(t, err2)
	assert.Equal(t, 10, stats2.Devices.Total)

	// DataSource should only be called once
	mockDS.AssertNumberOfCalls(t, "GetDeviceStats", 1)
}

func TestEngine_GetDashboardStats_NilDataSource(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	stats, err := engine.GetDashboardStats(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, 0, stats.Devices.Total)
}

func TestEngine_RecordMetric(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	labels := map[string]string{"device": "router-01"}
	engine.RecordMetric("test_metric", MetricTypeGauge, 42.5, labels)

	// Check in-memory metrics
	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	metrics, exists := engine.metrics["test_metric"]
	assert.True(t, exists)
	assert.Len(t, metrics, 1)
	assert.Equal(t, 42.5, metrics[0].Value)
	assert.Equal(t, "router-01", metrics[0].Labels["device"])
}

func TestEngine_IncrementCounter(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	labels := map[string]string{"action": "login"}
	engine.IncrementCounter("login_count", labels)
	engine.IncrementCounter("login_count", labels)
	engine.IncrementCounter("login_count", labels)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	metrics := engine.metrics["login_count"]
	assert.Len(t, metrics, 3)
	for _, m := range metrics {
		assert.Equal(t, float64(1), m.Value)
		assert.Equal(t, MetricTypeCounter, m.Type)
	}
}

func TestEngine_SetGauge(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	engine.SetGauge("cpu_usage", 75.5, map[string]string{"host": "server-01"})

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	metrics := engine.metrics["cpu_usage"]
	assert.Len(t, metrics, 1)
	assert.Equal(t, 75.5, metrics[0].Value)
	assert.Equal(t, MetricTypeGauge, metrics[0].Type)
}

func TestEngine_GetTimeSeries_InMemory(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	now := time.Now()
	engine.RecordMetric("test_series", MetricTypeGauge, 10, nil)
	engine.RecordMetric("test_series", MetricTypeGauge, 20, nil)
	engine.RecordMetric("test_series", MetricTypeGauge, 30, nil)

	ts, err := engine.GetTimeSeries(context.Background(), "test_series", now.Add(-time.Hour), now.Add(time.Hour), time.Minute)

	assert.NoError(t, err)
	assert.NotNil(t, ts)
	assert.Equal(t, "test_series", ts.Name)
	assert.Len(t, ts.Points, 3)
}

func TestEngine_GetTimeSeries_WithRepository(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	expectedTS := &TimeSeries{
		Name: "test_series",
		Points: []TimeSeriesPoint{
			{Timestamp: time.Now(), Value: 100},
		},
	}
	mockRepo.On("GetTimeSeries", mock.Anything, "test_series", mock.Anything, mock.Anything, mock.Anything).Return(expectedTS, nil)

	engine := NewEngine(mockRepo, nil, logger, nil)
	ts, err := engine.GetTimeSeries(context.Background(), "test_series", time.Now().Add(-time.Hour), time.Now(), time.Minute)

	assert.NoError(t, err)
	assert.Equal(t, expectedTS, ts)
	mockRepo.AssertExpectations(t)
}

func TestEngine_GetPolicyEvaluationTrend(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	trend, err := engine.GetPolicyEvaluationTrend(context.Background(), 24)

	assert.NoError(t, err)
	assert.Len(t, trend, 24)
	for _, point := range trend {
		assert.Contains(t, point, "time")
		assert.Contains(t, point, "allowed")
		assert.Contains(t, point, "denied")
	}
}

func TestEngine_GetDeviceStatusDistribution(t *testing.T) {
	logger := zap.NewNop()
	mockDS := new(MockDataSource)

	mockDS.On("GetDeviceStats", mock.Anything).Return(&DeviceStats{
		Total:       100,
		Online:      70,
		Offline:     20,
		Quarantined: 5,
		Unknown:     5,
	}, nil)
	mockDS.On("GetIdentityStats", mock.Anything).Return(&IdentityStats{}, nil)
	mockDS.On("GetCapabilityStats", mock.Anything).Return(&CapabilityStats{}, nil)
	mockDS.On("GetPolicyStats", mock.Anything).Return(&PolicyStats{}, nil)
	mockDS.On("GetDeploymentStats", mock.Anything).Return(&DeploymentStats{}, nil)
	mockDS.On("GetAuditStats", mock.Anything, mock.Anything, mock.Anything).Return(&AuditStats{}, nil)

	engine := NewEngine(nil, mockDS, logger, nil)
	dist, err := engine.GetDeviceStatusDistribution(context.Background())

	assert.NoError(t, err)
	assert.Len(t, dist, 4)

	// Check Online
	assert.Equal(t, "Online", dist[0]["name"])
	assert.Equal(t, 70, dist[0]["value"])
}

func TestEngine_GetConfigDeploymentTrend(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	trend, err := engine.GetConfigDeploymentTrend(context.Background(), 7)

	assert.NoError(t, err)
	assert.Len(t, trend, 7)
	for _, point := range trend {
		assert.Contains(t, point, "day")
		assert.Contains(t, point, "success")
		assert.Contains(t, point, "failed")
	}
}

func TestEngine_RecordPolicyEvaluation(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	policyID := uuid.New()
	engine.RecordPolicyEvaluation(models.PolicyEffectAllow, policyID, 10*time.Millisecond)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	// Check counter
	counters := engine.metrics["ztnms_policy_evaluations_total"]
	assert.NotEmpty(t, counters)

	// Check histogram
	durations := engine.metrics["ztnms_policy_evaluation_duration_ms"]
	assert.NotEmpty(t, durations)
	assert.Equal(t, float64(10), durations[0].Value)
}

func TestEngine_RecordAuthentication(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	engine.RecordAuthentication(true, models.IdentityTypeOperator)
	engine.RecordAuthentication(false, models.IdentityTypeDevice)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	metrics := engine.metrics["ztnms_authentications_total"]
	assert.Len(t, metrics, 2)
}

func TestEngine_RecordOperation(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	deviceID := uuid.New()
	engine.RecordOperation("ssh_connect", deviceID, true, 5*time.Second)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	counters := engine.metrics["ztnms_operations_total"]
	assert.NotEmpty(t, counters)
	assert.Equal(t, "ssh_connect", counters[0].Labels["operation"])

	durations := engine.metrics["ztnms_operation_duration_ms"]
	assert.NotEmpty(t, durations)
	assert.Equal(t, float64(5000), durations[0].Value)
}

func TestEngine_RecordAttestation(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	deviceID := uuid.New()
	engine.RecordAttestation(models.AttestationStatusVerified, deviceID)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	metrics := engine.metrics["ztnms_attestations_total"]
	assert.NotEmpty(t, metrics)
	assert.Equal(t, string(models.AttestationStatusVerified), metrics[0].Labels["status"])
}

func TestEngine_RecordConfigDeployment(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	deviceID := uuid.New()
	engine.RecordConfigDeployment("success", deviceID, 30*time.Second)

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	counters := engine.metrics["ztnms_config_deployments_total"]
	assert.NotEmpty(t, counters)
	assert.Equal(t, "success", counters[0].Labels["status"])

	durations := engine.metrics["ztnms_config_deployment_duration_ms"]
	assert.NotEmpty(t, durations)
	assert.Equal(t, float64(30000), durations[0].Value)
}

func TestEngine_StartStop(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, &Config{
		CollectInterval: 10 * time.Millisecond,
	})

	engine.Start()
	time.Sleep(50 * time.Millisecond)
	engine.Stop()

	// Should not panic
}

func TestEngine_CleanupOldMetrics(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, &Config{
		MetricsRetention: 1 * time.Millisecond,
	})

	// Add old metric
	engine.metricsMu.Lock()
	engine.metrics["old_metric"] = []*Metric{
		{Name: "old_metric", Timestamp: time.Now().Add(-time.Hour)},
	}
	engine.metricsMu.Unlock()

	// Run cleanup
	engine.cleanupOldMetrics()

	engine.metricsMu.RLock()
	defer engine.metricsMu.RUnlock()

	assert.Empty(t, engine.metrics["old_metric"])
}

func TestEngine_GetRecentEvents(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	events, err := engine.GetRecentEvents(context.Background(), 10)
	assert.NoError(t, err)
	assert.NotNil(t, events)
}

func TestEngine_GetTopDevicesByOperations(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	devices, err := engine.GetTopDevicesByOperations(context.Background(), 10)
	assert.NoError(t, err)
	assert.NotNil(t, devices)
}

func TestEngine_GetTopOperatorsByActivity(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	operators, err := engine.GetTopOperatorsByActivity(context.Background(), 10)
	assert.NoError(t, err)
	assert.NotNil(t, operators)
}

func TestEngine_GetSecurityTrend(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(nil, nil, logger, nil)

	trend, err := engine.GetSecurityTrend(context.Background(), 7)
	assert.NoError(t, err)
	assert.NotNil(t, trend)
}

func TestTimeSeries(t *testing.T) {
	ts := TimeSeries{
		Name:   "cpu_usage",
		Labels: map[string]string{"host": "server-01"},
		Points: []TimeSeriesPoint{
			{Timestamp: time.Now(), Value: 50.5},
			{Timestamp: time.Now().Add(time.Minute), Value: 60.0},
		},
	}

	assert.Equal(t, "cpu_usage", ts.Name)
	assert.Len(t, ts.Points, 2)
	assert.Equal(t, 50.5, ts.Points[0].Value)
}

func TestTimeSeriesPoint(t *testing.T) {
	point := TimeSeriesPoint{
		Timestamp: time.Now(),
		Value:     75.5,
		Labels:    map[string]string{"region": "us-east"},
	}

	assert.Equal(t, 75.5, point.Value)
	assert.Equal(t, "us-east", point.Labels["region"])
}
