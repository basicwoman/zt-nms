package config

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// Manager handles configuration management
type Manager struct {
	repo           Repository
	validator      Validator
	deploymentSvc  DeploymentService
	signingKey     ed25519.PrivateKey
	logger         *zap.Logger
	mu             sync.RWMutex
	pendingDeploys map[uuid.UUID]*DeploymentState
}

// Repository provides access to configuration data
type Repository interface {
	CreateBlock(ctx context.Context, block *models.ConfigBlock) error
	GetBlock(ctx context.Context, id uuid.UUID) (*models.ConfigBlock, error)
	GetLatestBlock(ctx context.Context, deviceID uuid.UUID) (*models.ConfigBlock, error)
	GetBlockBySequence(ctx context.Context, deviceID uuid.UUID, sequence int64) (*models.ConfigBlock, error)
	GetBlockHistory(ctx context.Context, deviceID uuid.UUID, limit, offset int) ([]*models.ConfigBlock, int, error)
	UpdateDeploymentStatus(ctx context.Context, id uuid.UUID, status models.DeploymentStatus) error
	VerifyChain(ctx context.Context, deviceID uuid.UUID) (bool, int64, error)
}

// Validator validates configurations
type Validator interface {
	ValidateSyntax(config *models.ConfigurationPayload) (*models.ValidationResult, error)
	ValidatePolicy(config *models.ConfigurationPayload, deviceID uuid.UUID) (*models.ValidationResult, error)
	ValidateSecurity(config *models.ConfigurationPayload) (*models.ValidationResult, error)
	SimulateDeployment(config *models.ConfigurationPayload, deviceID uuid.UUID) (*models.SimulationResult, error)
}

// DeploymentService handles configuration deployment
type DeploymentService interface {
	Prepare(ctx context.Context, block *models.ConfigBlock) error
	Commit(ctx context.Context, block *models.ConfigBlock) error
	Rollback(ctx context.Context, block *models.ConfigBlock) error
	Verify(ctx context.Context, block *models.ConfigBlock, checks []VerificationCheck) (*VerificationResult, error)
}

// DeploymentState tracks the state of a deployment
type DeploymentState struct {
	Block       *models.ConfigBlock
	Phase       DeploymentPhase
	StartedAt   time.Time
	PreparedAt  *time.Time
	CommittedAt *time.Time
	VerifiedAt  *time.Time
	Error       error
}

// DeploymentPhase represents the phase of deployment
type DeploymentPhase string

const (
	PhaseValidating DeploymentPhase = "validating"
	PhasePreparing  DeploymentPhase = "preparing"
	PhaseCommitting DeploymentPhase = "committing"
	PhaseVerifying  DeploymentPhase = "verifying"
	PhaseComplete   DeploymentPhase = "complete"
	PhaseFailed     DeploymentPhase = "failed"
	PhaseRolledBack DeploymentPhase = "rolled_back"
)

// VerificationCheck defines a post-deployment check
type VerificationCheck struct {
	Type       string            `json:"type"`
	Parameters map[string]string `json:"parameters"`
	Expected   string            `json:"expected"`
	Timeout    time.Duration     `json:"timeout"`
	Rollback   bool              `json:"rollback_on_failure"`
}

// VerificationResult contains verification results
type VerificationResult struct {
	Success bool                      `json:"success"`
	Checks  []VerificationCheckResult `json:"checks"`
}

// VerificationCheckResult contains a single check result
type VerificationCheckResult struct {
	Type    string `json:"type"`
	Success bool   `json:"success"`
	Actual  string `json:"actual"`
	Error   string `json:"error,omitempty"`
}

// NewManager creates a new configuration manager
func NewManager(repo Repository, validator Validator, deploymentSvc DeploymentService, signingKey ed25519.PrivateKey, logger *zap.Logger) *Manager {
	return &Manager{
		repo:           repo,
		validator:      validator,
		deploymentSvc:  deploymentSvc,
		signingKey:     signingKey,
		logger:         logger,
		pendingDeploys: make(map[uuid.UUID]*DeploymentState),
	}
}

// CreateConfigBlock creates a new configuration block
func (m *Manager) CreateConfigBlock(ctx context.Context, deviceID uuid.UUID, intent *models.ConfigIntent, config *models.ConfigurationPayload, authorID uuid.UUID) (*models.ConfigBlock, error) {
	// Get the latest block for this device
	latestBlock, err := m.repo.GetLatestBlock(ctx, deviceID)
	if err != nil && err != models.ErrConfigNotFound {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	var sequence int64 = 1
	var prevHash []byte

	if latestBlock != nil {
		sequence = latestBlock.Sequence + 1
		prevHash = latestBlock.BlockHash
	}

	// Calculate diff
	var diff *models.ConfigDiff
	if latestBlock != nil && latestBlock.Configuration != nil {
		diff = m.calculateDiff(latestBlock.Configuration, config)
	}

	// Validate configuration
	validation, err := m.validateConfig(config, deviceID)
	if err != nil {
		return nil, err
	}

	// Create the block
	block := models.NewConfigBlock(
		deviceID,
		sequence,
		prevHash,
		intent,
		config,
		diff,
		validation,
		authorID,
	)

	// Sign the block
	block.Sign(m.signingKey)

	// Store the block
	if err := m.repo.CreateBlock(ctx, block); err != nil {
		return nil, fmt.Errorf("failed to create config block: %w", err)
	}

	m.logger.Info("Created config block",
		zap.String("block_id", block.ID.String()),
		zap.String("device_id", deviceID.String()),
		zap.Int64("sequence", sequence),
	)

	return block, nil
}

// validateConfig validates a configuration
func (m *Manager) validateConfig(config *models.ConfigurationPayload, deviceID uuid.UUID) (*models.ValidationResult, error) {
	result := &models.ValidationResult{}

	// Syntax validation
	syntaxResult, err := m.validator.ValidateSyntax(config)
	if err != nil {
		return nil, err
	}
	result.SyntaxCheck = syntaxResult.SyntaxCheck
	result.Errors = append(result.Errors, syntaxResult.Errors...)
	result.Warnings = append(result.Warnings, syntaxResult.Warnings...)

	// Policy validation
	policyResult, err := m.validator.ValidatePolicy(config, deviceID)
	if err != nil {
		return nil, err
	}
	result.PolicyCheck = policyResult.PolicyCheck
	result.Errors = append(result.Errors, policyResult.Errors...)
	result.Warnings = append(result.Warnings, policyResult.Warnings...)

	// Security validation
	securityResult, err := m.validator.ValidateSecurity(config)
	if err != nil {
		return nil, err
	}
	result.SecurityCheck = securityResult.SecurityCheck
	result.Errors = append(result.Errors, securityResult.Errors...)
	result.Warnings = append(result.Warnings, securityResult.Warnings...)

	// Simulation
	simResult, err := m.validator.SimulateDeployment(config, deviceID)
	if err != nil {
		m.logger.Warn("Simulation failed", zap.Error(err))
	} else {
		result.SimulationResult = simResult
	}

	return result, nil
}

// calculateDiff calculates the difference between two configurations
func (m *Manager) calculateDiff(oldConfig, newConfig *models.ConfigurationPayload) *models.ConfigDiff {
	diff := &models.ConfigDiff{}

	if oldConfig.Tree == nil || newConfig.Tree == nil {
		return diff
	}

	// Compare interfaces
	if oldConfig.Tree.Interfaces != nil && newConfig.Tree.Interfaces != nil {
		for name, newIface := range newConfig.Tree.Interfaces {
			if oldIface, exists := oldConfig.Tree.Interfaces[name]; exists {
				// Check if modified
				oldJSON, _ := json.Marshal(oldIface)
				newJSON, _ := json.Marshal(newIface)
				if string(oldJSON) != string(newJSON) {
					diff.Modified = append(diff.Modified, models.ConfigChange{
						Path:     "interfaces." + name,
						OldValue: oldIface,
						NewValue: newIface,
					})
				}
			} else {
				diff.Added = append(diff.Added, models.ConfigChange{
					Path:     "interfaces." + name,
					NewValue: newIface,
				})
			}
		}
		for name, oldIface := range oldConfig.Tree.Interfaces {
			if _, exists := newConfig.Tree.Interfaces[name]; !exists {
				diff.Removed = append(diff.Removed, models.ConfigChange{
					Path:     "interfaces." + name,
					OldValue: oldIface,
				})
			}
		}
	}

	// Similar logic for other sections...
	return diff
}

// Deploy deploys a configuration block to a device
func (m *Manager) Deploy(ctx context.Context, blockID uuid.UUID, verificationChecks []VerificationCheck, rollbackOnFailure bool) error {
	block, err := m.repo.GetBlock(ctx, blockID)
	if err != nil {
		return err
	}

	// Check if already deployed
	if block.DeploymentStatus == models.DeploymentStatusApplied {
		return models.NewAPIError(models.CodeConfigInvalid, "configuration already deployed")
	}

	// Create deployment state
	state := &DeploymentState{
		Block:     block,
		Phase:     PhaseValidating,
		StartedAt: time.Now(),
	}

	m.mu.Lock()
	m.pendingDeploys[blockID] = state
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pendingDeploys, blockID)
		m.mu.Unlock()
	}()

	// Phase 1: Validate
	m.logger.Info("Deployment phase: validating", zap.String("block_id", blockID.String()))
	if len(block.Validation.Errors) > 0 {
		state.Phase = PhaseFailed
		state.Error = models.ErrConfigValidationFailed
		return models.ErrConfigValidationFailed
	}

	// Phase 2: Prepare (2PC prepare)
	m.logger.Info("Deployment phase: preparing", zap.String("block_id", blockID.String()))
	state.Phase = PhasePreparing

	if err := m.deploymentSvc.Prepare(ctx, block); err != nil {
		state.Phase = PhaseFailed
		state.Error = err
		m.repo.UpdateDeploymentStatus(ctx, blockID, models.DeploymentStatusFailed)
		return fmt.Errorf("prepare failed: %w", err)
	}

	now := time.Now()
	state.PreparedAt = &now

	// Phase 3: Commit (2PC commit)
	m.logger.Info("Deployment phase: committing", zap.String("block_id", blockID.String()))
	state.Phase = PhaseCommitting

	if err := m.deploymentSvc.Commit(ctx, block); err != nil {
		state.Phase = PhaseFailed
		state.Error = err
		m.repo.UpdateDeploymentStatus(ctx, blockID, models.DeploymentStatusFailed)
		return fmt.Errorf("commit failed: %w", err)
	}

	now = time.Now()
	state.CommittedAt = &now

	// Phase 4: Verify
	if len(verificationChecks) > 0 {
		m.logger.Info("Deployment phase: verifying", zap.String("block_id", blockID.String()))
		state.Phase = PhaseVerifying

		result, err := m.deploymentSvc.Verify(ctx, block, verificationChecks)
		if err != nil || !result.Success {
			if rollbackOnFailure {
				m.logger.Warn("Verification failed, rolling back", zap.String("block_id", blockID.String()))
				state.Phase = PhaseRolledBack

				if rbErr := m.deploymentSvc.Rollback(ctx, block); rbErr != nil {
					m.logger.Error("Rollback failed", zap.Error(rbErr))
				}

				m.repo.UpdateDeploymentStatus(ctx, blockID, models.DeploymentStatusRolledBack)
				return fmt.Errorf("verification failed: %w", err)
			}
		}

		now = time.Now()
		state.VerifiedAt = &now
	}

	// Success
	state.Phase = PhaseComplete
	m.repo.UpdateDeploymentStatus(ctx, blockID, models.DeploymentStatusApplied)

	m.logger.Info("Deployment completed",
		zap.String("block_id", blockID.String()),
		zap.String("device_id", block.DeviceID.String()),
		zap.Int64("sequence", block.Sequence),
	)

	return nil
}

// Rollback rolls back to a previous configuration
func (m *Manager) Rollback(ctx context.Context, deviceID uuid.UUID, targetSequence int64, authorID uuid.UUID, reason string) (*models.ConfigBlock, error) {
	// Get target block
	targetBlock, err := m.repo.GetBlockBySequence(ctx, deviceID, targetSequence)
	if err != nil {
		return nil, err
	}

	// Create a new block with the old configuration
	intent := &models.ConfigIntent{
		Description:  fmt.Sprintf("Rollback to sequence %d: %s", targetSequence, reason),
		ChangeTicket: "", // Should be provided
	}

	newBlock, err := m.CreateConfigBlock(ctx, deviceID, intent, targetBlock.Configuration, authorID)
	if err != nil {
		return nil, err
	}

	// Deploy the rollback
	if err := m.Deploy(ctx, newBlock.ID, nil, false); err != nil {
		return nil, err
	}

	m.logger.Info("Rolled back configuration",
		zap.String("device_id", deviceID.String()),
		zap.Int64("from_sequence", targetBlock.Sequence+1),
		zap.Int64("to_sequence", targetSequence),
		zap.String("new_block", newBlock.ID.String()),
	)

	return newBlock, nil
}

// GetBlock retrieves a configuration block
func (m *Manager) GetBlock(ctx context.Context, id uuid.UUID) (*models.ConfigBlock, error) {
	return m.repo.GetBlock(ctx, id)
}

// GetLatest retrieves the latest configuration for a device
func (m *Manager) GetLatest(ctx context.Context, deviceID uuid.UUID) (*models.ConfigBlock, error) {
	return m.repo.GetLatestBlock(ctx, deviceID)
}

// GetHistory retrieves configuration history for a device
func (m *Manager) GetHistory(ctx context.Context, deviceID uuid.UUID, limit, offset int) ([]*models.ConfigBlock, int, error) {
	return m.repo.GetBlockHistory(ctx, deviceID, limit, offset)
}

// VerifyChain verifies the integrity of the configuration chain
func (m *Manager) VerifyChain(ctx context.Context, deviceID uuid.UUID) (bool, int64, error) {
	return m.repo.VerifyChain(ctx, deviceID)
}

// GetDeploymentState gets the state of a pending deployment
func (m *Manager) GetDeploymentState(blockID uuid.UUID) *DeploymentState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pendingDeploys[blockID]
}

// CompareConfigs compares two configurations
func (m *Manager) CompareConfigs(ctx context.Context, deviceID uuid.UUID, seq1, seq2 int64) (*models.ConfigDiff, error) {
	block1, err := m.repo.GetBlockBySequence(ctx, deviceID, seq1)
	if err != nil {
		return nil, err
	}

	block2, err := m.repo.GetBlockBySequence(ctx, deviceID, seq2)
	if err != nil {
		return nil, err
	}

	return m.calculateDiff(block1.Configuration, block2.Configuration), nil
}

// ExportConfig exports a configuration to JSON
func (m *Manager) ExportConfig(ctx context.Context, blockID uuid.UUID) ([]byte, error) {
	block, err := m.repo.GetBlock(ctx, blockID)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(block.Configuration, "", "  ")
}
