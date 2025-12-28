package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// Repository provides access to identity data
type Repository interface {
	// Create creates a new identity
	Create(ctx context.Context, identity *models.Identity) error
	// GetByID retrieves an identity by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error)
	// GetByPublicKey retrieves an identity by public key
	GetByPublicKey(ctx context.Context, publicKey ed25519.PublicKey) (*models.Identity, error)
	// GetByUsername retrieves an operator identity by username
	GetByUsername(ctx context.Context, username string) (*models.Identity, error)
	// Update updates an identity
	Update(ctx context.Context, identity *models.Identity) error
	// UpdateStatus updates the status of an identity
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.IdentityStatus) error
	// Delete deletes an identity (soft delete - sets status to revoked)
	Delete(ctx context.Context, id uuid.UUID) error
	// List lists identities with filtering
	List(ctx context.Context, filter IdentityFilter, limit, offset int) ([]*models.Identity, int, error)
	// GetByGroup retrieves identities by group
	GetByGroup(ctx context.Context, group string) ([]*models.Identity, error)
	// VerifyPassword verifies operator password
	VerifyPassword(ctx context.Context, identityID uuid.UUID, password string) error
}

// IdentityFilter defines filtering options for listing identities
type IdentityFilter struct {
	Type      models.IdentityType
	Status    models.IdentityStatus
	Groups    []string
	CreatedBy *uuid.UUID
	Search    string
}

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// Create creates a new identity
func (r *PostgresRepository) Create(ctx context.Context, identity *models.Identity) error {
	attributesJSON, err := json.Marshal(identity.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		INSERT INTO identities (id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err = r.pool.Exec(ctx, query,
		identity.ID,
		identity.Type,
		attributesJSON,
		identity.PublicKey,
		identity.Certificate,
		identity.Status,
		identity.CreatedAt,
		identity.UpdatedAt,
		identity.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	return nil
}

// GetByID retrieves an identity by ID
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	query := `
		SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by
		FROM identities
		WHERE id = $1
	`

	row := r.pool.QueryRow(ctx, query, id)
	return r.scanIdentity(row)
}

// GetByPublicKey retrieves an identity by public key
func (r *PostgresRepository) GetByPublicKey(ctx context.Context, publicKey ed25519.PublicKey) (*models.Identity, error) {
	query := `
		SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by
		FROM identities
		WHERE public_key = $1
	`

	row := r.pool.QueryRow(ctx, query, []byte(publicKey))
	return r.scanIdentity(row)
}

// GetByUsername retrieves an operator identity by username
func (r *PostgresRepository) GetByUsername(ctx context.Context, username string) (*models.Identity, error) {
	query := `
		SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by
		FROM identities
		WHERE type = 'operator' AND attributes->>'username' = $1
	`

	row := r.pool.QueryRow(ctx, query, username)
	return r.scanIdentity(row)
}

// Update updates an identity
func (r *PostgresRepository) Update(ctx context.Context, identity *models.Identity) error {
	attributesJSON, err := json.Marshal(identity.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		UPDATE identities
		SET attributes = $2, certificate = $3, status = $4, updated_at = $5
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query,
		identity.ID,
		attributesJSON,
		identity.Certificate,
		identity.Status,
		time.Now().UTC(),
	)

	if err != nil {
		return fmt.Errorf("failed to update identity: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrIdentityNotFound
	}

	return nil
}

// UpdateStatus updates the status of an identity
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.IdentityStatus) error {
	query := `
		UPDATE identities
		SET status = $2, updated_at = $3
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query, id, status, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update identity status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrIdentityNotFound
	}

	return nil
}

// Delete soft-deletes an identity
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.UpdateStatus(ctx, id, models.IdentityStatusRevoked)
}

// List lists identities with filtering
func (r *PostgresRepository) List(ctx context.Context, filter IdentityFilter, limit, offset int) ([]*models.Identity, int, error) {
	// Build dynamic query
	baseQuery := `FROM identities WHERE 1=1`
	countQuery := `SELECT COUNT(*) ` + baseQuery
	selectQuery := `SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by ` + baseQuery

	args := make([]interface{}, 0)
	argNum := 1

	if filter.Type != "" {
		baseQuery += fmt.Sprintf(" AND type = $%d", argNum)
		args = append(args, filter.Type)
		argNum++
	}

	if filter.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, filter.Status)
		argNum++
	}

	if filter.CreatedBy != nil {
		baseQuery += fmt.Sprintf(" AND created_by = $%d", argNum)
		args = append(args, filter.CreatedBy)
		argNum++
	}

	if len(filter.Groups) > 0 {
		baseQuery += fmt.Sprintf(" AND attributes->'groups' ?| $%d", argNum)
		args = append(args, filter.Groups)
		argNum++
	}

	if filter.Search != "" {
		baseQuery += fmt.Sprintf(" AND (attributes->>'username' ILIKE $%d OR attributes->>'hostname' ILIKE $%d OR attributes->>'name' ILIKE $%d)", argNum, argNum, argNum)
		args = append(args, "%"+filter.Search+"%")
		argNum++
	}

	// Get count
	countQuery = `SELECT COUNT(*) ` + baseQuery[len("FROM identities WHERE 1=1"):]
	countQuery = `SELECT COUNT(*) FROM identities WHERE 1=1` + baseQuery[len("FROM identities WHERE 1=1"):]
	
	var total int
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count identities: %w", err)
	}

	// Get data with pagination
	selectQuery = `SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by FROM identities WHERE 1=1` + baseQuery[len("FROM identities WHERE 1=1"):]
	selectQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query identities: %w", err)
	}
	defer rows.Close()

	identities := make([]*models.Identity, 0)
	for rows.Next() {
		identity, err := r.scanIdentityFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		identities = append(identities, identity)
	}

	return identities, total, nil
}

// GetByGroup retrieves identities by group
func (r *PostgresRepository) GetByGroup(ctx context.Context, group string) ([]*models.Identity, error) {
	query := `
		SELECT id, type, attributes, public_key, certificate, status, created_at, updated_at, created_by
		FROM identities
		WHERE type = 'operator' AND attributes->'groups' ? $1 AND status = 'active'
	`

	rows, err := r.pool.Query(ctx, query, group)
	if err != nil {
		return nil, fmt.Errorf("failed to query identities by group: %w", err)
	}
	defer rows.Close()

	identities := make([]*models.Identity, 0)
	for rows.Next() {
		identity, err := r.scanIdentityFromRows(rows)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}

	return identities, nil
}

func (r *PostgresRepository) scanIdentity(row pgx.Row) (*models.Identity, error) {
	var identity models.Identity
	var attributesJSON []byte

	err := row.Scan(
		&identity.ID,
		&identity.Type,
		&attributesJSON,
		&identity.PublicKey,
		&identity.Certificate,
		&identity.Status,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrIdentityNotFound
		}
		return nil, fmt.Errorf("failed to scan identity: %w", err)
	}

	if err := json.Unmarshal(attributesJSON, &identity.Attributes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
	}

	return &identity, nil
}

func (r *PostgresRepository) scanIdentityFromRows(rows pgx.Rows) (*models.Identity, error) {
	var identity models.Identity
	var attributesJSON []byte

	err := rows.Scan(
		&identity.ID,
		&identity.Type,
		&attributesJSON,
		&identity.PublicKey,
		&identity.Certificate,
		&identity.Status,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.CreatedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan identity: %w", err)
	}

	if err := json.Unmarshal(attributesJSON, &identity.Attributes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
	}

	return &identity, nil
}

// VerifyPassword verifies operator password from operators table
func (r *PostgresRepository) VerifyPassword(ctx context.Context, identityID uuid.UUID, password string) error {
	query := `
		SELECT password_hash FROM operators WHERE identity_id = $1
	`

	var passwordHash string
	err := r.pool.QueryRow(ctx, query, identityID).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ErrAuthenticationFailed
		}
		return fmt.Errorf("failed to get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return models.ErrAuthenticationFailed
	}

	// Update last login
	updateQuery := `
		UPDATE operators SET last_login = $2, login_count = login_count + 1, failed_attempts = 0
		WHERE identity_id = $1
	`
	r.pool.Exec(ctx, updateQuery, identityID, time.Now().UTC())

	return nil
}
