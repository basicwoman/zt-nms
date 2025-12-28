package config_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/config"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockRepository implements config.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateBlock(ctx context.Context, block *models.ConfigBlock) error {
	args := m.Called(ctx, block)
	return args.Error(0)
}

func (m *MockRepository) GetBlock(ctx context.Context, id uuid.UUID) (*models.ConfigBlock, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) GetLatestBlock(ctx context.Context, deviceID uuid.UUID) (*models.ConfigBlock, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) GetBlockBySequence(ctx context.Context, deviceID uuid.UUID, sequence int64) (*models.ConfigBlock, error) {
	args := m.Called(ctx, deviceID, sequence)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ConfigBlock), args.Error(1)
}

func (m *MockRepository) GetBlockHistory(ctx context.Context, deviceID uuid.UUID, limit, offset int) ([]*models.ConfigBlock, int, error) {
	args := m.Called(ctx, deviceID, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*models.ConfigBlock), args.Int(1), args.Error(2)
}

func (m *MockRepository) UpdateDeploymentStatus(ctx context.Context, id uuid.UUID, status models.DeploymentStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRepository) VerifyChain(ctx context.Context, deviceID uuid.UUID) (bool, int64, error) {
	args := m.Called(ctx, deviceID)
	return args.Bool(0), args.Get(1).(int64), args.Error(2)
}

// MockValidator implements config.Validator
type MockValidator struct {
	mock.Mock
}

func (m *MockValidator) ValidateSyntax(config *models.ConfigurationPayload) (*models.ValidationResult, error) {
	args := m.Called(config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ValidationResult), args.Error(1)
}

func (m *MockValidator) ValidatePolicy(config *models.ConfigurationPayload, deviceID uuid.UUID) (*models.ValidationResult, error) {
	args := m.Called(config, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ValidationResult), args.Error(1)
}

func (m *MockValidator) ValidateSecurity(config *models.ConfigurationPayload) (*models.ValidationResult, error) {
	args := m.Called(config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ValidationResult), args.Error(1)
}

func (m *MockValidator) SimulateDeployment(config *models.ConfigurationPayload, deviceID uuid.UUID) (*models.SimulationResult, error) {
	args := m.Called(config, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SimulationResult), args.Error(1)
}

// MockDeploymentService implements config.DeploymentService
type MockDeploymentService struct {
	mock.Mock
}

func (m *MockDeploymentService) Prepare(ctx context.Context, block *models.ConfigBlock) error {
	args := m.Called(ctx, block)
	return args.Error(0)
}

func (m *MockDeploymentService) Commit(ctx context.Context, block *models.ConfigBlock) error {
	args := m.Called(ctx, block)
	return args.Error(0)
}

func (m *MockDeploymentService) Rollback(ctx context.Context, block *models.ConfigBlock) error {
	args := m.Called(ctx, block)
	return args.Error(0)
}

func (m *MockDeploymentService) Verify(ctx context.Context, block *models.ConfigBlock, checks []config.VerificationCheck) (*config.VerificationResult, error) {
	args := m.Called(ctx, block, checks)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*config.VerificationResult), args.Error(1)
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func createTestPayload() *models.ConfigurationPayload {
	return &models.ConfigurationPayload{
		Format: models.ConfigFormatNormalized,
		Tree: &models.ConfigTree{
			System: &models.SystemConfig{
				Hostname: "test-router",
			},
			Interfaces: map[string]models.InterfaceConfig{
				"eth0": {
					Enabled:   true,
					IPAddress: "10.0.0.1/24",
				},
			},
		},
	}
}

func createTestIntent() *models.ConfigIntent {
	return &models.ConfigIntent{
		Description:  "Test configuration change",
		ChangeTicket: "TICKET-123",
	}
}

func createTestBlock(deviceID uuid.UUID) *models.ConfigBlock {
	_, privKey := generateKeyPair()
	authorID := uuid.New()
	block := models.NewConfigBlock(
		deviceID,
		1,
		nil,
		createTestIntent(),
		createTestPayload(),
		nil,
		&models.ValidationResult{SyntaxCheck: "pass"},
		authorID,
	)
	block.Sign(privKey)
	return block
}

func createManager(t *testing.T, mockRepo *MockRepository, mockValidator *MockValidator, mockDeploy *MockDeploymentService) *config.Manager {
	logger := zap.NewNop()
	_, privKey := generateKeyPair()

	manager := config.NewManager(mockRepo, mockValidator, mockDeploy, privKey, logger)
	return manager
}

func TestNewManager(t *testing.T) {
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)
	logger := zap.NewNop()
	_, privKey := generateKeyPair()

	manager := config.NewManager(mockRepo, mockValidator, mockDeploy, privKey, logger)
	assert.NotNil(t, manager)
}

func TestGetBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	blockID := uuid.New()
	expectedBlock := createTestBlock(deviceID)
	expectedBlock.ID = blockID

	mockRepo.On("GetBlock", ctx, blockID).Return(expectedBlock, nil)

	block, err := manager.GetBlock(ctx, blockID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, blockID, block.ID)
	mockRepo.AssertExpectations(t)
}

func TestGetLatest(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	expectedBlock := createTestBlock(deviceID)

	mockRepo.On("GetLatestBlock", ctx, deviceID).Return(expectedBlock, nil)

	block, err := manager.GetLatest(ctx, deviceID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, deviceID, block.DeviceID)
	mockRepo.AssertExpectations(t)
}

func TestGetHistory(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	expectedBlocks := []*models.ConfigBlock{
		createTestBlock(deviceID),
		createTestBlock(deviceID),
	}
	expectedBlocks[1].Sequence = 2

	mockRepo.On("GetBlockHistory", ctx, deviceID, 50, 0).Return(expectedBlocks, 2, nil)

	blocks, total, err := manager.GetHistory(ctx, deviceID, 50, 0)

	assert.NoError(t, err)
	assert.Len(t, blocks, 2)
	assert.Equal(t, 2, total)
	mockRepo.AssertExpectations(t)
}

func TestVerifyChain(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()

	mockRepo.On("VerifyChain", ctx, deviceID).Return(true, int64(10), nil)

	valid, lastSeq, err := manager.VerifyChain(ctx, deviceID)

	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, int64(10), lastSeq)
	mockRepo.AssertExpectations(t)
}

func TestConfigBlock_SignAndVerify(t *testing.T) {
	deviceID := uuid.New()
	pub, priv := generateKeyPair()
	authorID := uuid.New()

	block := models.NewConfigBlock(
		deviceID,
		1,
		nil,
		createTestIntent(),
		createTestPayload(),
		nil,
		&models.ValidationResult{SyntaxCheck: "pass"},
		authorID,
	)

	// Sign
	block.Sign(priv)
	assert.NotEmpty(t, block.AuthorSignature)
	assert.NotEmpty(t, block.BlockHash)

	// Verify with correct key
	assert.True(t, block.Verify(pub))

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	assert.False(t, block.Verify(wrongPub))
}

func TestConfigBlock_Hash(t *testing.T) {
	deviceID := uuid.New()
	block := createTestBlock(deviceID)

	hash1 := block.ComputeHash()
	hash2 := block.ComputeHash()

	// Hash should be deterministic
	assert.Equal(t, hash1, hash2)
}

func TestNewConfigBlock(t *testing.T) {
	deviceID := uuid.New()
	authorID := uuid.New()
	prevHash := []byte("previous-hash")
	intent := createTestIntent()
	payload := createTestPayload()

	block := models.NewConfigBlock(
		deviceID,
		5,
		prevHash,
		intent,
		payload,
		nil,
		nil,
		authorID,
	)

	assert.NotNil(t, block)
	assert.NotEqual(t, uuid.Nil, block.ID)
	assert.Equal(t, deviceID, block.DeviceID)
	assert.Equal(t, int64(5), block.Sequence)
	assert.Equal(t, prevHash, block.PrevHash)
	assert.Equal(t, intent, block.Intent)
	assert.Equal(t, payload, block.Configuration)
	assert.Equal(t, authorID, block.AuthorID)
	assert.False(t, block.Timestamp.IsZero())
}

func TestConfigurationPayload(t *testing.T) {
	payload := createTestPayload()

	assert.NotNil(t, payload)
	assert.Equal(t, models.ConfigFormatNormalized, payload.Format)
	assert.NotNil(t, payload.Tree)
	assert.Equal(t, "test-router", payload.Tree.System.Hostname)
	assert.Len(t, payload.Tree.Interfaces, 1)
}

func TestDeploymentPhases(t *testing.T) {
	// Test deployment phase constants
	assert.Equal(t, config.DeploymentPhase("validating"), config.PhaseValidating)
	assert.Equal(t, config.DeploymentPhase("preparing"), config.PhasePreparing)
	assert.Equal(t, config.DeploymentPhase("committing"), config.PhaseCommitting)
	assert.Equal(t, config.DeploymentPhase("verifying"), config.PhaseVerifying)
	assert.Equal(t, config.DeploymentPhase("complete"), config.PhaseComplete)
	assert.Equal(t, config.DeploymentPhase("failed"), config.PhaseFailed)
	assert.Equal(t, config.DeploymentPhase("rolled_back"), config.PhaseRolledBack)
}

func TestDeploymentState(t *testing.T) {
	deviceID := uuid.New()
	block := createTestBlock(deviceID)

	state := &config.DeploymentState{
		Block:     block,
		Phase:     config.PhasePreparing,
		StartedAt: time.Now().UTC(),
	}

	assert.NotNil(t, state)
	assert.Equal(t, block, state.Block)
	assert.Equal(t, config.PhasePreparing, state.Phase)
	assert.False(t, state.StartedAt.IsZero())
}

func TestVerificationCheck(t *testing.T) {
	check := config.VerificationCheck{
		Type:       "connectivity",
		Parameters: map[string]string{"target": "10.0.0.1"},
		Expected:   "success",
		Timeout:    30 * time.Second,
		Rollback:   true,
	}

	assert.Equal(t, "connectivity", check.Type)
	assert.Equal(t, "10.0.0.1", check.Parameters["target"])
	assert.True(t, check.Rollback)
}

func TestVerificationResult(t *testing.T) {
	result := &config.VerificationResult{
		Success: true,
		Checks: []config.VerificationCheckResult{
			{Type: "connectivity", Success: true, Actual: "success"},
			{Type: "config_sync", Success: true, Actual: "synced"},
		},
	}

	assert.True(t, result.Success)
	assert.Len(t, result.Checks, 2)
}

// Benchmark tests
func BenchmarkBlockSign(b *testing.B) {
	deviceID := uuid.New()
	_, privKey := generateKeyPair()
	authorID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := models.NewConfigBlock(
			deviceID,
			int64(i+1),
			nil,
			createTestIntent(),
			createTestPayload(),
			nil,
			nil,
			authorID,
		)
		block.Sign(privKey)
	}
}

func BenchmarkBlockVerify(b *testing.B) {
	deviceID := uuid.New()
	pub, priv := generateKeyPair()
	authorID := uuid.New()

	block := models.NewConfigBlock(
		deviceID,
		1,
		nil,
		createTestIntent(),
		createTestPayload(),
		nil,
		nil,
		authorID,
	)
	block.Sign(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block.Verify(pub)
	}
}

func BenchmarkBlockHash(b *testing.B) {
	deviceID := uuid.New()
	block := createTestBlock(deviceID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block.ComputeHash()
	}
}

// Additional tests for higher coverage

func TestCreateConfigBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	authorID := uuid.New()
	payload := createTestPayload()
	intent := createTestIntent()

	// Mock responses
	mockRepo.On("GetLatestBlock", ctx, deviceID).Return(nil, models.ErrConfigNotFound)
	mockRepo.On("CreateBlock", ctx, mock.AnythingOfType("*models.ConfigBlock")).Return(nil)

	mockValidator.On("ValidateSyntax", payload).Return(&models.ValidationResult{SyntaxCheck: "pass"}, nil)
	mockValidator.On("ValidatePolicy", payload, deviceID).Return(&models.ValidationResult{PolicyCheck: "pass"}, nil)
	mockValidator.On("ValidateSecurity", payload).Return(&models.ValidationResult{SecurityCheck: "pass"}, nil)
	mockValidator.On("SimulateDeployment", payload, deviceID).Return(&models.SimulationResult{Reachability: "pass"}, nil)

	block, err := manager.CreateConfigBlock(ctx, deviceID, intent, payload, authorID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, deviceID, block.DeviceID)
	assert.Equal(t, int64(1), block.Sequence)
	assert.NotEmpty(t, block.AuthorSignature)
	mockRepo.AssertExpectations(t)
	mockValidator.AssertExpectations(t)
}

func TestCreateConfigBlock_WithPreviousBlock(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	authorID := uuid.New()
	payload := createTestPayload()
	intent := createTestIntent()

	// Previous block exists
	prevBlock := createTestBlock(deviceID)
	prevBlock.Sequence = 5

	mockRepo.On("GetLatestBlock", ctx, deviceID).Return(prevBlock, nil)
	mockRepo.On("CreateBlock", ctx, mock.AnythingOfType("*models.ConfigBlock")).Return(nil)

	mockValidator.On("ValidateSyntax", payload).Return(&models.ValidationResult{SyntaxCheck: "pass"}, nil)
	mockValidator.On("ValidatePolicy", payload, deviceID).Return(&models.ValidationResult{PolicyCheck: "pass"}, nil)
	mockValidator.On("ValidateSecurity", payload).Return(&models.ValidationResult{SecurityCheck: "pass"}, nil)
	mockValidator.On("SimulateDeployment", payload, deviceID).Return(&models.SimulationResult{Reachability: "pass"}, nil)

	block, err := manager.CreateConfigBlock(ctx, deviceID, intent, payload, authorID)

	assert.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, int64(6), block.Sequence)
	assert.Equal(t, prevBlock.BlockHash, block.PrevHash)
	mockRepo.AssertExpectations(t)
}

func TestDeploy_Success(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.Validation = &models.ValidationResult{SyntaxCheck: "pass"}
	block.DeploymentStatus = models.DeploymentStatusPending

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockDeploy.On("Prepare", ctx, block).Return(nil)
	mockDeploy.On("Commit", ctx, block).Return(nil)
	mockRepo.On("UpdateDeploymentStatus", ctx, block.ID, models.DeploymentStatusApplied).Return(nil)

	err := manager.Deploy(ctx, block.ID, nil, false)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockDeploy.AssertExpectations(t)
}

func TestDeploy_AlreadyDeployed(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusApplied

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)

	err := manager.Deploy(ctx, block.ID, nil, false)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

func TestDeploy_ValidationFailed(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusPending
	block.Validation = &models.ValidationResult{
		Errors: []models.ConfigValidationError{{Code: "ERR001", Message: "syntax error"}},
	}

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)

	err := manager.Deploy(ctx, block.ID, nil, false)

	assert.Error(t, err)
	assert.Equal(t, models.ErrConfigValidationFailed, err)
}

func TestDeploy_PrepareFailed(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusPending
	block.Validation = &models.ValidationResult{SyntaxCheck: "pass"}

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockDeploy.On("Prepare", ctx, block).Return(assert.AnError)
	mockRepo.On("UpdateDeploymentStatus", ctx, block.ID, models.DeploymentStatusFailed).Return(nil)

	err := manager.Deploy(ctx, block.ID, nil, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "prepare failed")
}

func TestDeploy_CommitFailed(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusPending
	block.Validation = &models.ValidationResult{SyntaxCheck: "pass"}

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockDeploy.On("Prepare", ctx, block).Return(nil)
	mockDeploy.On("Commit", ctx, block).Return(assert.AnError)
	mockRepo.On("UpdateDeploymentStatus", ctx, block.ID, models.DeploymentStatusFailed).Return(nil)

	err := manager.Deploy(ctx, block.ID, nil, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "commit failed")
}

func TestDeploy_WithVerification(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusPending
	block.Validation = &models.ValidationResult{SyntaxCheck: "pass"}

	checks := []config.VerificationCheck{
		{Type: "connectivity", Expected: "success"},
	}

	verifyResult := &config.VerificationResult{
		Success: true,
		Checks:  []config.VerificationCheckResult{{Type: "connectivity", Success: true}},
	}

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockDeploy.On("Prepare", ctx, block).Return(nil)
	mockDeploy.On("Commit", ctx, block).Return(nil)
	mockDeploy.On("Verify", ctx, block, checks).Return(verifyResult, nil)
	mockRepo.On("UpdateDeploymentStatus", ctx, block.ID, models.DeploymentStatusApplied).Return(nil)

	err := manager.Deploy(ctx, block.ID, checks, true)

	assert.NoError(t, err)
	mockDeploy.AssertExpectations(t)
}

func TestDeploy_VerificationFailedWithRollback(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)
	block.DeploymentStatus = models.DeploymentStatusPending
	block.Validation = &models.ValidationResult{SyntaxCheck: "pass"}

	checks := []config.VerificationCheck{
		{Type: "connectivity", Expected: "success", Rollback: true},
	}

	verifyResult := &config.VerificationResult{
		Success: false,
		Checks:  []config.VerificationCheckResult{{Type: "connectivity", Success: false}},
	}

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)
	mockDeploy.On("Prepare", ctx, block).Return(nil)
	mockDeploy.On("Commit", ctx, block).Return(nil)
	mockDeploy.On("Verify", ctx, block, checks).Return(verifyResult, nil)
	mockDeploy.On("Rollback", ctx, block).Return(nil)
	mockRepo.On("UpdateDeploymentStatus", ctx, block.ID, models.DeploymentStatusRolledBack).Return(nil)

	err := manager.Deploy(ctx, block.ID, checks, true)

	assert.Error(t, err)
	mockDeploy.AssertCalled(t, "Rollback", ctx, block)
}

func TestCompareConfigs(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block1 := createTestBlock(deviceID)
	block1.Sequence = 1

	block2 := createTestBlock(deviceID)
	block2.Sequence = 2
	block2.Configuration.Tree.System.Hostname = "new-router"

	mockRepo.On("GetBlockBySequence", ctx, deviceID, int64(1)).Return(block1, nil)
	mockRepo.On("GetBlockBySequence", ctx, deviceID, int64(2)).Return(block2, nil)

	diff, err := manager.CompareConfigs(ctx, deviceID, 1, 2)

	assert.NoError(t, err)
	assert.NotNil(t, diff)
	mockRepo.AssertExpectations(t)
}

func TestExportConfig(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	block := createTestBlock(deviceID)

	mockRepo.On("GetBlock", ctx, block.ID).Return(block, nil)

	data, err := manager.ExportConfig(ctx, block.ID)

	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "test-router")
	mockRepo.AssertExpectations(t)
}

func TestGetDeploymentState(t *testing.T) {
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	blockID := uuid.New()

	// Initially nil
	state := manager.GetDeploymentState(blockID)
	assert.Nil(t, state)
}

func TestGetBlock_NotFound(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	blockID := uuid.New()
	mockRepo.On("GetBlock", ctx, blockID).Return(nil, models.ErrConfigNotFound)

	block, err := manager.GetBlock(ctx, blockID)

	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Equal(t, models.ErrConfigNotFound, err)
}

func TestGetLatest_NotFound(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	mockRepo.On("GetLatestBlock", ctx, deviceID).Return(nil, models.ErrConfigNotFound)

	block, err := manager.GetLatest(ctx, deviceID)

	assert.Error(t, err)
	assert.Nil(t, block)
}

func TestVerifyChain_Invalid(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	mockValidator := new(MockValidator)
	mockDeploy := new(MockDeploymentService)

	manager := createManager(t, mockRepo, mockValidator, mockDeploy)

	deviceID := uuid.New()
	mockRepo.On("VerifyChain", ctx, deviceID).Return(false, int64(5), nil)

	valid, seq, err := manager.VerifyChain(ctx, deviceID)

	assert.NoError(t, err)
	assert.False(t, valid)
	assert.Equal(t, int64(5), seq)
}
