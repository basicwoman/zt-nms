package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// Repository provides access to policy data
type Repository interface {
	Create(ctx context.Context, policy *models.Policy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error)
	Update(ctx context.Context, policy *models.Policy) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, policyType models.PolicyType, status models.PolicyStatus, limit, offset int) ([]*models.Policy, int, error)
	GetActive(ctx context.Context) ([]*models.Policy, error)
}

// Cache provides caching for policy decisions
type Cache interface {
	Get(key string) (*models.PolicyDecision, bool)
	Set(key string, decision *models.PolicyDecision, ttl time.Duration)
	Clear()
}

// InMemoryCache implements Cache in memory
type InMemoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	decision  *models.PolicyDecision
	expiresAt time.Time
}

func NewInMemoryCache() *InMemoryCache {
	c := &InMemoryCache{entries: make(map[string]cacheEntry)}
	go c.cleanup()
	return c
}

func (c *InMemoryCache) Get(key string) (*models.PolicyDecision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.decision, true
}

func (c *InMemoryCache) Set(key string, decision *models.PolicyDecision, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{decision: decision, expiresAt: time.Now().Add(ttl)}
}

func (c *InMemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

func (c *InMemoryCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// Engine provides policy evaluation services
type Engine struct {
	repo     Repository
	cache    Cache
	logger   *zap.Logger
	mu       sync.RWMutex
	policies map[uuid.UUID]*models.Policy
}

func NewEngine(repo Repository, cache Cache, logger *zap.Logger) *Engine {
	return &Engine{
		repo:     repo,
		cache:    cache,
		logger:   logger,
		policies: make(map[uuid.UUID]*models.Policy),
	}
}

func (e *Engine) LoadPolicies(ctx context.Context) error {
	policies, err := e.repo.GetActive(ctx)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = make(map[uuid.UUID]*models.Policy)
	for _, p := range policies {
		e.policies[p.ID] = p
	}

	e.logger.Info("Loaded policies", zap.Int("count", len(policies)))
	return nil
}

func (e *Engine) Evaluate(ctx context.Context, req models.PolicyEvaluationRequest) (*models.PolicyDecision, error) {
	cacheKey := e.buildCacheKey(req)
	if e.cache != nil {
		if cached, ok := e.cache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	decision := &models.PolicyDecision{
		Decision:    models.PolicyEffectDeny,
		EvaluatedAt: time.Now().UTC(),
		CacheKey:    cacheKey,
		CacheTTL:    60,
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if policy.Status != models.PolicyStatusActive {
			continue
		}

		now := time.Now()
		if policy.EffectiveFrom != nil && now.Before(*policy.EffectiveFrom) {
			continue
		}
		if policy.EffectiveUntil != nil && now.After(*policy.EffectiveUntil) {
			continue
		}

		policyDecision := policy.Evaluate(req)
		if len(policyDecision.MatchedRules) > 0 {
			decision.MatchedRules = append(decision.MatchedRules, policyDecision.MatchedRules...)
			decision.Obligations = append(decision.Obligations, policyDecision.Obligations...)

			if policyDecision.Decision == models.PolicyEffectDeny {
				decision.Decision = models.PolicyEffectDeny
				decision.Reason = policyDecision.Reason
				break
			}

			if policyDecision.Decision == models.PolicyEffectAllow {
				decision.Decision = models.PolicyEffectAllow
			}

			if policyDecision.Decision == models.PolicyEffectStepUp && decision.Decision != models.PolicyEffectDeny {
				decision.Decision = models.PolicyEffectStepUp
			}
		}
	}

	if e.cache != nil && decision.CacheTTL > 0 {
		e.cache.Set(cacheKey, decision, time.Duration(decision.CacheTTL)*time.Second)
	}

	e.logger.Debug("Policy evaluated",
		zap.String("subject", req.Subject.ID.String()),
		zap.String("resource", req.Resource.ID),
		zap.String("action", req.Action),
		zap.String("decision", string(decision.Decision)),
	)

	return decision, nil
}

func (e *Engine) buildCacheKey(req models.PolicyEvaluationRequest) string {
	return fmt.Sprintf("%s:%s:%s:%s", req.Subject.ID.String(), req.Resource.Type, req.Resource.ID, req.Action)
}

func (e *Engine) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	if err := e.validatePolicy(policy); err != nil {
		return err
	}

	if err := e.repo.Create(ctx, policy); err != nil {
		return err
	}

	if policy.Status == models.PolicyStatusActive {
		e.mu.Lock()
		e.policies[policy.ID] = policy
		e.mu.Unlock()
	}

	if e.cache != nil {
		e.cache.Clear()
	}

	e.logger.Info("Created policy", zap.String("id", policy.ID.String()), zap.String("name", policy.Name))
	return nil
}

func (e *Engine) UpdatePolicy(ctx context.Context, policy *models.Policy) error {
	if err := e.validatePolicy(policy); err != nil {
		return err
	}

	policy.Version++

	if err := e.repo.Update(ctx, policy); err != nil {
		return err
	}

	e.mu.Lock()
	if policy.Status == models.PolicyStatusActive {
		e.policies[policy.ID] = policy
	} else {
		delete(e.policies, policy.ID)
	}
	e.mu.Unlock()

	if e.cache != nil {
		e.cache.Clear()
	}

	return nil
}

func (e *Engine) validatePolicy(policy *models.Policy) error {
	if policy.Name == "" {
		return models.NewAPIError(models.CodePolicyInvalid, "policy name is required")
	}
	if len(policy.Definition.Rules) == 0 {
		return models.NewAPIError(models.CodePolicyInvalid, "policy must have at least one rule")
	}
	return nil
}

func (e *Engine) EmergencyAccess(ctx context.Context, req models.PolicyEvaluationRequest) (*models.PolicyDecision, error) {
	if req.Context.Emergency == nil || !req.Context.Emergency.Declared {
		return nil, models.NewAPIError(models.CodeAccessDenied, "emergency access not declared")
	}

	decision := &models.PolicyDecision{
		Decision:    models.PolicyEffectAllow,
		EvaluatedAt: time.Now().UTC(),
		Reason:      "Emergency access granted",
		Obligations: []models.Obligation{
			{Type: models.ObligationTypeAudit, Parameters: map[string]interface{}{"emergency_id": req.Context.Emergency.EmergencyID}},
			{Type: models.ObligationTypeRecordSession},
			{Type: models.ObligationTypeAlert, Parameters: map[string]interface{}{"level": "critical"}},
		},
	}

	e.logger.Warn("Emergency access granted",
		zap.String("subject", req.Subject.ID.String()),
		zap.String("emergency_id", req.Context.Emergency.EmergencyID),
	)

	return decision, nil
}

func (e *Engine) ExportPolicy(ctx context.Context, id uuid.UUID) ([]byte, error) {
	policy, err := e.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(policy, "", "  ")
}

// GetPolicy retrieves a policy by ID
func (e *Engine) GetPolicy(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	return e.repo.GetByID(ctx, id)
}

// ListPolicies lists policies with filtering
func (e *Engine) ListPolicies(ctx context.Context, policyType models.PolicyType, status models.PolicyStatus, limit, offset int) ([]*models.Policy, int, error) {
	return e.repo.List(ctx, policyType, status, limit, offset)
}
