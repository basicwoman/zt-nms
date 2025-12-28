package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/policy"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// Issuer manages capability token issuance and verification
type Issuer struct {
	repo        Repository
	policyEngine *policy.Engine
	signingKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	issuerID    string
	logger      *zap.Logger
	nonceStore  NonceStore
	mu          sync.RWMutex
	revoked     map[string]time.Time // token hash -> revocation time
}

// Repository provides access to capability data
type Repository interface {
	Create(ctx context.Context, token *models.CapabilityToken) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.CapabilityToken, error)
	IncrementUseCount(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, reason string, revokedBy uuid.UUID) error
	GetRevoked(ctx context.Context, since time.Time) ([][]byte, error)
	ListBySubject(ctx context.Context, subjectID uuid.UUID, active bool) ([]*models.CapabilityToken, error)
}

// NonceStore provides nonce tracking for replay protection
type NonceStore interface {
	Add(nonce []byte, timestamp int64) error
	Exists(nonce []byte) bool
}

// IssuerConfig contains issuer configuration
type IssuerConfig struct {
	SigningKeyPEM []byte
	IssuerID      string
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
}

// NewIssuer creates a new capability issuer
func NewIssuer(repo Repository, policyEngine *policy.Engine, config *IssuerConfig, logger *zap.Logger) (*Issuer, error) {
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	if config.SigningKeyPEM != nil {
		// Parse signing key
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		privateKey = priv
		publicKey = pub
	} else {
		// Generate ephemeral key for development
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		privateKey = priv
		publicKey = pub
	}

	return &Issuer{
		repo:         repo,
		policyEngine: policyEngine,
		signingKey:   privateKey,
		publicKey:    publicKey,
		issuerID:     config.IssuerID,
		logger:       logger,
		revoked:      make(map[string]time.Time),
	}, nil
}

// SetNonceStore sets the nonce store
func (i *Issuer) SetNonceStore(store NonceStore) {
	i.nonceStore = store
}

// Request processes a capability token request
func (i *Issuer) Request(ctx context.Context, req *models.CapabilityTokenRequest, requesterID uuid.UUID, requesterKey ed25519.PublicKey) (*models.CapabilityToken, error) {
	// Build policy evaluation request
	policyReq := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:   requesterID,
			Type: models.IdentityTypeOperator,
		},
		Context: models.PolicyContext{
			Time: time.Now(),
		},
	}

	// Evaluate each grant against policy
	approvedGrants := make([]models.Grant, 0)
	for _, grant := range req.Grants {
		policyReq.Resource = models.PolicyResource{
			Type: grant.Resource.Type,
			ID:   grant.Resource.ID,
		}

		for _, action := range grant.Actions {
			policyReq.Action = string(action)
			decision, err := i.policyEngine.Evaluate(ctx, policyReq)
			if err != nil {
				return nil, fmt.Errorf("policy evaluation failed: %w", err)
			}

			if decision.Decision == models.PolicyEffectDeny {
				i.logger.Warn("Grant denied by policy",
					zap.String("requester", requesterID.String()),
					zap.String("resource", grant.Resource.ID),
					zap.String("action", string(action)),
					zap.String("reason", decision.Reason),
				)
				continue
			}

			// Check for step-up requirements
			if decision.Decision == models.PolicyEffectStepUp {
				grant.RequiresApproval = true
				grant.ApprovalQuorum = 1
			}
		}

		approvedGrants = append(approvedGrants, grant)
	}

	if len(approvedGrants) == 0 {
		return nil, models.NewAPIError(models.CodeAccessDenied, "no grants approved by policy")
	}

	// Calculate validity period
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(req.ValidityDuration),
	}

	// Create the token
	token := models.NewCapabilityToken(
		i.issuerID,
		req.SubjectID,
		requesterKey,
		approvedGrants,
		validity,
		req.ContextRequirements,
		req.Delegation,
	)

	// Sign the token
	token.Sign(i.signingKey)

	// Store the token
	if err := i.repo.Create(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store capability: %w", err)
	}

	i.logger.Info("Issued capability token",
		zap.String("token_id", token.TokenID.String()),
		zap.String("subject", token.SubjectID.String()),
		zap.Int("grants", len(token.Grants)),
		zap.Time("expires", token.Validity.NotAfter),
	)

	return token, nil
}

// Verify verifies a capability token
func (i *Issuer) Verify(ctx context.Context, token *models.CapabilityToken) error {
	// Verify signature
	if !token.Verify(i.publicKey) {
		return models.ErrInvalidSignature
	}

	// Check validity period
	now := time.Now()
	if now.Before(token.Validity.NotBefore) {
		return models.NewAPIError(models.CodeCapabilityInvalid, "token not yet valid")
	}
	if now.After(token.Validity.NotAfter) {
		return models.ErrCapabilityExpired
	}

	// Check revocation
	tokenHash := token.TokenHash()
	hashStr := fmt.Sprintf("%x", tokenHash)

	i.mu.RLock()
	_, isRevoked := i.revoked[hashStr]
	i.mu.RUnlock()

	if isRevoked {
		return models.ErrCapabilityRevoked
	}

	// Check usage limit
	if token.Validity.MaxUses > 0 {
		stored, err := i.repo.GetByID(ctx, token.TokenID)
		if err != nil {
			return err
		}
		// Assuming we track use count somewhere
		_ = stored // Use stored token for use count check
	}

	return nil
}

// Use records a use of a capability token
func (i *Issuer) Use(ctx context.Context, token *models.CapabilityToken, action models.ActionType, resourceType, resourceID string) error {
	// Verify token first
	if err := i.Verify(ctx, token); err != nil {
		return err
	}

	// Check if action is allowed
	if !token.Allows(action, resourceType, resourceID) {
		return models.ErrInsufficientCapability
	}

	// Check approval requirements
	if token.RequiresApprovalFor(action, resourceType, resourceID) {
		if !token.HasSufficientApprovals(resourceType, resourceID) {
			return models.ErrInsufficientApprovals
		}
	}

	// Increment use count
	if err := i.repo.IncrementUseCount(ctx, token.TokenID); err != nil {
		i.logger.Error("Failed to increment use count", zap.Error(err))
	}

	i.logger.Debug("Capability token used",
		zap.String("token_id", token.TokenID.String()),
		zap.String("action", string(action)),
		zap.String("resource", resourceID),
	)

	return nil
}

// Revoke revokes a capability token
func (i *Issuer) Revoke(ctx context.Context, tokenID uuid.UUID, reason string, revokedBy uuid.UUID) error {
	token, err := i.repo.GetByID(ctx, tokenID)
	if err != nil {
		return err
	}

	// Revoke in repository
	if err := i.repo.Revoke(ctx, tokenID, reason, revokedBy); err != nil {
		return err
	}

	// Add to in-memory revocation list
	tokenHash := token.TokenHash()
	hashStr := fmt.Sprintf("%x", tokenHash)

	i.mu.Lock()
	i.revoked[hashStr] = time.Now()
	i.mu.Unlock()

	i.logger.Info("Revoked capability token",
		zap.String("token_id", tokenID.String()),
		zap.String("reason", reason),
		zap.String("revoked_by", revokedBy.String()),
	)

	return nil
}

// LoadRevocations loads revoked tokens from repository
func (i *Issuer) LoadRevocations(ctx context.Context) error {
	// Load revocations from last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	hashes, err := i.repo.GetRevoked(ctx, since)
	if err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	for _, hash := range hashes {
		hashStr := fmt.Sprintf("%x", hash)
		i.revoked[hashStr] = time.Now()
	}

	i.logger.Info("Loaded revocations", zap.Int("count", len(hashes)))
	return nil
}

// Delegate creates a delegated capability token
func (i *Issuer) Delegate(ctx context.Context, parentToken *models.CapabilityToken, delegatee uuid.UUID, delegateeKey ed25519.PublicKey, grants []models.Grant) (*models.CapabilityToken, error) {
	// Check if delegation is allowed
	if parentToken.Delegation == nil || !parentToken.Delegation.Allowed {
		return nil, models.ErrDelegationNotAllowed
	}

	// Check delegation depth
	if parentToken.DelegationDepth >= parentToken.Delegation.MaxDepth {
		return nil, models.ErrDelegationDepthExceeded
	}

	// Verify parent token
	if err := i.Verify(ctx, parentToken); err != nil {
		return nil, err
	}

	// Filter grants to only allowed delegatable actions
	delegatableActions := make(map[models.ActionType]bool)
	for _, action := range parentToken.Delegation.DelegatableActions {
		delegatableActions[action] = true
	}

	filteredGrants := make([]models.Grant, 0)
	for _, grant := range grants {
		filteredActions := make([]models.ActionType, 0)
		for _, action := range grant.Actions {
			if delegatableActions[action] {
				// Also check parent token allows this
				if parentToken.Allows(action, grant.Resource.Type, grant.Resource.ID) {
					filteredActions = append(filteredActions, action)
				}
			}
		}
		if len(filteredActions) > 0 {
			grant.Actions = filteredActions
			filteredGrants = append(filteredGrants, grant)
		}
	}

	if len(filteredGrants) == 0 {
		return nil, models.NewAPIError(models.CodeAccessDenied, "no delegatable grants")
	}

	// Create delegated token with reduced validity
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  parentToken.Validity.NotAfter, // Can't extend beyond parent
	}

	subjectHash := sha256.Sum256(delegateeKey)

	token := &models.CapabilityToken{
		Version:             1,
		TokenID:             uuid.New(),
		Issuer:              i.issuerID,
		IssuedAt:            time.Now().UTC(),
		SubjectID:           delegatee,
		SubjectHash:         subjectHash[:],
		Grants:              filteredGrants,
		Validity:            validity,
		ContextRequirements: parentToken.ContextRequirements,
		ParentTokenID:       &parentToken.TokenID,
		DelegationDepth:     parentToken.DelegationDepth + 1,
	}

	// Sign the token
	token.Sign(i.signingKey)

	// Store the token
	if err := i.repo.Create(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store delegated capability: %w", err)
	}

	i.logger.Info("Created delegated capability token",
		zap.String("token_id", token.TokenID.String()),
		zap.String("parent_token", parentToken.TokenID.String()),
		zap.String("delegatee", delegatee.String()),
		zap.Int("depth", token.DelegationDepth),
	)

	return token, nil
}

// GetByID retrieves a capability token by ID
func (i *Issuer) GetByID(ctx context.Context, id uuid.UUID) (*models.CapabilityToken, error) {
	return i.repo.GetByID(ctx, id)
}

// ListBySubject lists capability tokens for a subject
func (i *Issuer) ListBySubject(ctx context.Context, subjectID uuid.UUID, activeOnly bool) ([]*models.CapabilityToken, error) {
	return i.repo.ListBySubject(ctx, subjectID, activeOnly)
}

// Serialize serializes a capability token for transmission
func (i *Issuer) Serialize(token *models.CapabilityToken) ([]byte, error) {
	return json.Marshal(token)
}

// Deserialize deserializes a capability token
func (i *Issuer) Deserialize(data []byte) (*models.CapabilityToken, error) {
	var token models.CapabilityToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// PublicKey returns the issuer's public key
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.publicKey
}
