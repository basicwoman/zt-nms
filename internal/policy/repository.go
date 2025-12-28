package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// NewPostgresRepository creates a new PostgreSQL repository for policies
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// Create creates a new policy
func (r *PostgresRepository) Create(ctx context.Context, policy *models.Policy) error {
	definitionJSON, err := json.Marshal(policy.Definition)
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}

	query := `
		INSERT INTO policies (id, name, description, type, definition, version, status, effective_from, effective_until, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}

	_, err = r.pool.Exec(ctx, query,
		policy.ID,
		policy.Name,
		policy.Description,
		policy.Type,
		definitionJSON,
		policy.Version,
		policy.Status,
		policy.EffectiveFrom,
		policy.EffectiveUntil,
		policy.CreatedAt,
		now,
		policy.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// GetByID retrieves a policy by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	query := `
		SELECT id, name, description, type, definition, version, status, effective_from, effective_until, created_at, created_by
		FROM policies
		WHERE id = $1
	`

	row := r.pool.QueryRow(ctx, query, id)
	return r.scanPolicy(row)
}

// Update updates a policy
func (r *PostgresRepository) Update(ctx context.Context, policy *models.Policy) error {
	definitionJSON, err := json.Marshal(policy.Definition)
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}

	query := `
		UPDATE policies
		SET name = $2, description = $3, type = $4, definition = $5, version = $6, status = $7, effective_from = $8, effective_until = $9, updated_at = $10
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query,
		policy.ID,
		policy.Name,
		policy.Description,
		policy.Type,
		definitionJSON,
		policy.Version,
		policy.Status,
		policy.EffectiveFrom,
		policy.EffectiveUntil,
		time.Now().UTC(),
	)

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.NewAPIError(models.CodePolicyNotFound, "policy not found")
	}

	return nil
}

// Delete deletes a policy
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM policies WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.NewAPIError(models.CodePolicyNotFound, "policy not found")
	}

	return nil
}

// List lists policies with filtering
func (r *PostgresRepository) List(ctx context.Context, policyType models.PolicyType, status models.PolicyStatus, limit, offset int) ([]*models.Policy, int, error) {
	baseQuery := `FROM policies WHERE 1=1`
	args := make([]interface{}, 0)
	argNum := 1

	if policyType != "" {
		baseQuery += fmt.Sprintf(" AND type = $%d", argNum)
		args = append(args, policyType)
		argNum++
	}

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, status)
		argNum++
	}

	// Get count
	countQuery := `SELECT COUNT(*) ` + baseQuery
	var total int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count policies: %w", err)
	}

	// Get data with pagination
	selectQuery := `SELECT id, name, description, type, definition, version, status, effective_from, effective_until, created_at, created_by ` + baseQuery
	selectQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*models.Policy, 0)
	for rows.Next() {
		policy, err := r.scanPolicyFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		policies = append(policies, policy)
	}

	return policies, total, nil
}

// GetActive retrieves all active policies
func (r *PostgresRepository) GetActive(ctx context.Context) ([]*models.Policy, error) {
	query := `
		SELECT id, name, description, type, definition, version, status, effective_from, effective_until, created_at, created_by
		FROM policies
		WHERE status = 'active'
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*models.Policy, 0)
	for rows.Next() {
		policy, err := r.scanPolicyFromRows(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func (r *PostgresRepository) scanPolicy(row pgx.Row) (*models.Policy, error) {
	var policy models.Policy
	var definitionJSON []byte

	err := row.Scan(
		&policy.ID,
		&policy.Name,
		&policy.Description,
		&policy.Type,
		&definitionJSON,
		&policy.Version,
		&policy.Status,
		&policy.EffectiveFrom,
		&policy.EffectiveUntil,
		&policy.CreatedAt,
		&policy.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.NewAPIError(models.CodePolicyNotFound, "policy not found")
		}
		return nil, fmt.Errorf("failed to scan policy: %w", err)
	}

	if err := json.Unmarshal(definitionJSON, &policy.Definition); err != nil {
		return nil, fmt.Errorf("failed to unmarshal definition: %w", err)
	}

	return &policy, nil
}

func (r *PostgresRepository) scanPolicyFromRows(rows pgx.Rows) (*models.Policy, error) {
	var policy models.Policy
	var definitionJSON []byte

	err := rows.Scan(
		&policy.ID,
		&policy.Name,
		&policy.Description,
		&policy.Type,
		&definitionJSON,
		&policy.Version,
		&policy.Status,
		&policy.EffectiveFrom,
		&policy.EffectiveUntil,
		&policy.CreatedAt,
		&policy.CreatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan policy: %w", err)
	}

	if err := json.Unmarshal(definitionJSON, &policy.Definition); err != nil {
		return nil, fmt.Errorf("failed to unmarshal definition: %w", err)
	}

	return &policy, nil
}
