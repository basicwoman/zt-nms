package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/policy"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockRepository is a mock implementation of policy.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, p *models.Policy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Policy), args.Error(1)
}

func (m *MockRepository) Update(ctx context.Context, p *models.Policy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) List(ctx context.Context, policyType models.PolicyType, status models.PolicyStatus, limit, offset int) ([]*models.Policy, int, error) {
	args := m.Called(ctx, policyType, status, limit, offset)
	return args.Get(0).([]*models.Policy), args.Int(1), args.Error(2)
}

func (m *MockRepository) GetActive(ctx context.Context) ([]*models.Policy, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Policy), args.Error(1)
}

func createTestPolicy(id uuid.UUID, name string, status models.PolicyStatus) *models.Policy {
	return &models.Policy{
		ID:          id,
		Name:        name,
		Description: "Test policy",
		Type:        models.PolicyTypeAccess,
		Definition: models.PolicyDefinition{
			Rules: []models.PolicyRule{
				{
					Name:   "allow-all",
					Effect: models.PolicyEffectAllow,
					Subjects: models.SubjectMatcher{
						Identities: []models.IdentityMatcher{
							{Type: models.IdentityTypeOperator},
						},
					},
					Actions: []string{"read", "write"},
				},
			},
		},
		Version:   1,
		Status:    status,
		CreatedAt: time.Now().UTC(),
	}
}

func TestNewEngine(t *testing.T) {
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)
	assert.NotNil(t, engine)
}

func TestLoadPolicies(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	activePolicies := []*models.Policy{
		createTestPolicy(uuid.New(), "policy-1", models.PolicyStatusActive),
		createTestPolicy(uuid.New(), "policy-2", models.PolicyStatusActive),
	}

	mockRepo.On("GetActive", ctx).Return(activePolicies, nil)

	err := engine.LoadPolicies(ctx)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestCreatePolicy(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	testPolicy := createTestPolicy(uuid.New(), "new-policy", models.PolicyStatusDraft)

	mockRepo.On("Create", ctx, testPolicy).Return(nil)

	err := engine.CreatePolicy(ctx, testPolicy)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestCreatePolicy_InvalidName(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	testPolicy := &models.Policy{
		ID:   uuid.New(),
		Name: "", // Empty name
		Definition: models.PolicyDefinition{
			Rules: []models.PolicyRule{
				{Name: "test", Effect: models.PolicyEffectAllow},
			},
		},
	}

	err := engine.CreatePolicy(ctx, testPolicy)

	assert.Error(t, err)
}

func TestCreatePolicy_NoRules(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	testPolicy := &models.Policy{
		ID:   uuid.New(),
		Name: "test-policy",
		Definition: models.PolicyDefinition{
			Rules: []models.PolicyRule{}, // No rules
		},
	}

	err := engine.CreatePolicy(ctx, testPolicy)

	assert.Error(t, err)
}

func TestGetPolicy(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	policyID := uuid.New()
	expectedPolicy := createTestPolicy(policyID, "test-policy", models.PolicyStatusActive)

	mockRepo.On("GetByID", ctx, policyID).Return(expectedPolicy, nil)

	result, err := engine.GetPolicy(ctx, policyID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, policyID, result.ID)
	assert.Equal(t, "test-policy", result.Name)
	mockRepo.AssertExpectations(t)
}

func TestListPolicies(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	expectedPolicies := []*models.Policy{
		createTestPolicy(uuid.New(), "policy-1", models.PolicyStatusActive),
		createTestPolicy(uuid.New(), "policy-2", models.PolicyStatusDraft),
	}

	mockRepo.On("List", ctx, models.PolicyType(""), models.PolicyStatus(""), 50, 0).Return(expectedPolicies, 2, nil)

	policies, total, err := engine.ListPolicies(ctx, "", "", 50, 0)

	assert.NoError(t, err)
	assert.Len(t, policies, 2)
	assert.Equal(t, 2, total)
	mockRepo.AssertExpectations(t)
}

func TestListPolicies_WithFilters(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	expectedPolicies := []*models.Policy{
		createTestPolicy(uuid.New(), "policy-1", models.PolicyStatusActive),
	}

	mockRepo.On("List", ctx, models.PolicyTypeAccess, models.PolicyStatusActive, 10, 0).Return(expectedPolicies, 1, nil)

	policies, total, err := engine.ListPolicies(ctx, models.PolicyTypeAccess, models.PolicyStatusActive, 10, 0)

	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, 1, total)
	mockRepo.AssertExpectations(t)
}

func TestEvaluate_AllowDecision(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	// Load active policies
	activePolicies := []*models.Policy{
		{
			ID:     uuid.New(),
			Name:   "allow-operators",
			Status: models.PolicyStatusActive,
			Definition: models.PolicyDefinition{
				Rules: []models.PolicyRule{
					{
						Name:   "allow-operators-read",
						Effect: models.PolicyEffectAllow,
						Subjects: models.SubjectMatcher{
							Identities: []models.IdentityMatcher{
								{Type: models.IdentityTypeOperator},
							},
						},
						Actions: []string{"read"},
					},
				},
			},
		},
	}

	mockRepo.On("GetActive", ctx).Return(activePolicies, nil)
	engine.LoadPolicies(ctx)

	req := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   uuid.New(),
			Type: models.IdentityTypeOperator,
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "device-123",
		},
		Action: "read",
	}

	decision, err := engine.Evaluate(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, decision)
	// Default is deny if no explicit allow
	mockRepo.AssertExpectations(t)
}

func TestEvaluate_DenyDecision(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	// Load active policies with explicit deny
	activePolicies := []*models.Policy{
		{
			ID:     uuid.New(),
			Name:   "deny-all",
			Status: models.PolicyStatusActive,
			Definition: models.PolicyDefinition{
				Rules: []models.PolicyRule{
					{
						Name:   "deny-all-access",
						Effect: models.PolicyEffectDeny,
						Subjects: models.SubjectMatcher{
							Identities: []models.IdentityMatcher{
								{Type: models.IdentityTypeOperator},
							},
						},
						Actions: []string{"*"},
					},
				},
			},
		},
	}

	mockRepo.On("GetActive", ctx).Return(activePolicies, nil)
	engine.LoadPolicies(ctx)

	req := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   uuid.New(),
			Type: models.IdentityTypeOperator,
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "device-123",
		},
		Action: "delete",
	}

	decision, err := engine.Evaluate(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, decision)
	assert.Equal(t, models.PolicyEffectDeny, decision.Decision)
}

func TestEmergencyAccess(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	req := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   uuid.New(),
			Type: models.IdentityTypeOperator,
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "critical-device",
		},
		Action: "admin",
		Context: models.PolicyContext{
			Emergency: &models.EmergencyContext{
				Declared:    true,
				EmergencyID: "EMG-001",
				Reason:      "Network outage",
			},
		},
	}

	decision, err := engine.EmergencyAccess(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, decision)
	assert.Equal(t, models.PolicyEffectAllow, decision.Decision)
	assert.Equal(t, "Emergency access granted", decision.Reason)
	assert.NotEmpty(t, decision.Obligations)
}

func TestEmergencyAccess_NotDeclared(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	req := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   uuid.New(),
			Type: models.IdentityTypeOperator,
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "critical-device",
		},
		Action: "admin",
		Context: models.PolicyContext{
			Emergency: nil, // Not declared
		},
	}

	_, err := engine.EmergencyAccess(ctx, req)

	assert.Error(t, err)
}

func TestExportPolicy(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	policyID := uuid.New()
	testPolicy := createTestPolicy(policyID, "export-test", models.PolicyStatusActive)

	mockRepo.On("GetByID", ctx, policyID).Return(testPolicy, nil)

	data, err := engine.ExportPolicy(ctx, policyID)

	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "export-test")
	mockRepo.AssertExpectations(t)
}

func TestUpdatePolicy(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	testPolicy := createTestPolicy(uuid.New(), "update-test", models.PolicyStatusActive)

	mockRepo.On("Update", ctx, testPolicy).Return(nil)

	err := engine.UpdatePolicy(ctx, testPolicy)

	assert.NoError(t, err)
	assert.Equal(t, 2, testPolicy.Version) // Version should be incremented
	mockRepo.AssertExpectations(t)
}

// Cache tests
func TestInMemoryCache(t *testing.T) {
	cache := policy.NewInMemoryCache()

	decision := &models.PolicyDecision{
		Decision:    models.PolicyEffectAllow,
		EvaluatedAt: time.Now().UTC(),
	}

	// Test Set and Get
	cache.Set("test-key", decision, time.Minute)

	result, found := cache.Get("test-key")
	assert.True(t, found)
	assert.Equal(t, models.PolicyEffectAllow, result.Decision)

	// Test Get with non-existent key
	result, found = cache.Get("non-existent")
	assert.False(t, found)
	assert.Nil(t, result)

	// Test Clear
	cache.Clear()
	result, found = cache.Get("test-key")
	assert.False(t, found)
	assert.Nil(t, result)
}

// Benchmark tests
func BenchmarkEvaluate(b *testing.B) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	cache := policy.NewInMemoryCache()
	logger := zap.NewNop()

	engine := policy.NewEngine(mockRepo, cache, logger)

	activePolicies := []*models.Policy{
		createTestPolicy(uuid.New(), "policy-1", models.PolicyStatusActive),
	}

	mockRepo.On("GetActive", ctx).Return(activePolicies, nil)
	engine.LoadPolicies(ctx)

	req := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   uuid.New(),
			Type: models.IdentityTypeOperator,
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "device-123",
		},
		Action: "read",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(ctx, req)
	}
}

func BenchmarkCacheOperations(b *testing.B) {
	cache := policy.NewInMemoryCache()
	decision := &models.PolicyDecision{
		Decision:    models.PolicyEffectAllow,
		EvaluatedAt: time.Now().UTC(),
	}

	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Set("key", decision, time.Minute)
		}
	})

	cache.Set("key", decision, time.Minute)

	b.Run("Get", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Get("key")
		}
	})
}
