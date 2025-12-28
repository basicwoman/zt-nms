package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements Repository for PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// CreateDevice creates a new device
func (r *PostgresRepository) CreateDevice(ctx context.Context, device *Device) error {
	query := `
		INSERT INTO devices (id, identity_id, hostname, vendor, model, serial_number, os_type, os_version,
			role, criticality, location_id, management_ip, status, trust_status, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err := r.pool.Exec(ctx, query,
		device.ID, device.IdentityID, device.Hostname, device.Vendor, device.Model, device.SerialNumber,
		device.OSType, device.OSVersion, device.Role, device.Criticality,
		device.LocationID, device.ManagementIP, device.Status, device.TrustStatus, device.Metadata)
	return err
}

// GetDevice retrieves a device by ID
func (r *PostgresRepository) GetDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	query := `
		SELECT id, identity_id, hostname, vendor, model, serial_number, os_type, os_version,
			role, criticality, location_id, management_ip::text, status, trust_status, last_seen,
			current_config_sequence, metadata, created_at, updated_at
		FROM devices WHERE id = $1
	`
	device := &Device{}
	var locationID sql.NullString
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&device.ID, &device.IdentityID, &device.Hostname, &device.Vendor, &device.Model,
		&device.SerialNumber, &device.OSType, &device.OSVersion,
		&device.Role, &device.Criticality, &locationID, &device.ManagementIP,
		&device.Status, &device.TrustStatus, &device.LastSeen,
		&device.ConfigSequence, &device.Metadata, &device.CreatedAt, &device.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	if locationID.Valid {
		locID, _ := uuid.Parse(locationID.String)
		device.LocationID = &locID
	}
	return device, nil
}

// GetDeviceByHostname retrieves a device by hostname
func (r *PostgresRepository) GetDeviceByHostname(ctx context.Context, hostname string) (*Device, error) {
	query := `
		SELECT id, identity_id, hostname, vendor, model, serial_number, os_type, os_version,
			role, criticality, location_id, management_ip::text, status, trust_status, last_seen,
			current_config_sequence, metadata, created_at, updated_at
		FROM devices WHERE hostname = $1
	`
	device := &Device{}
	var locationID sql.NullString
	err := r.pool.QueryRow(ctx, query, hostname).Scan(
		&device.ID, &device.IdentityID, &device.Hostname, &device.Vendor, &device.Model,
		&device.SerialNumber, &device.OSType, &device.OSVersion,
		&device.Role, &device.Criticality, &locationID, &device.ManagementIP,
		&device.Status, &device.TrustStatus, &device.LastSeen,
		&device.ConfigSequence, &device.Metadata, &device.CreatedAt, &device.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	if locationID.Valid {
		locID, _ := uuid.Parse(locationID.String)
		device.LocationID = &locID
	}
	return device, nil
}

// GetDeviceByIP retrieves a device by management IP
func (r *PostgresRepository) GetDeviceByIP(ctx context.Context, ip string) (*Device, error) {
	query := `
		SELECT id, identity_id, hostname, vendor, model, serial_number, os_type, os_version,
			role, criticality, location_id, management_ip::text, status, trust_status, last_seen,
			current_config_sequence, metadata, created_at, updated_at
		FROM devices WHERE management_ip = $1
	`
	device := &Device{}
	var locationID sql.NullString
	err := r.pool.QueryRow(ctx, query, ip).Scan(
		&device.ID, &device.IdentityID, &device.Hostname, &device.Vendor, &device.Model,
		&device.SerialNumber, &device.OSType, &device.OSVersion,
		&device.Role, &device.Criticality, &locationID, &device.ManagementIP,
		&device.Status, &device.TrustStatus, &device.LastSeen,
		&device.ConfigSequence, &device.Metadata, &device.CreatedAt, &device.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	if locationID.Valid {
		locID, _ := uuid.Parse(locationID.String)
		device.LocationID = &locID
	}
	return device, nil
}

// UpdateDevice updates a device
func (r *PostgresRepository) UpdateDevice(ctx context.Context, device *Device) error {
	query := `
		UPDATE devices SET hostname = $2, vendor = $3, model = $4, serial_number = $5, os_type = $6,
			os_version = $7, role = $8, criticality = $9, location_id = $10, management_ip = $11,
			metadata = $12, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, device.ID, device.Hostname, device.Vendor, device.Model,
		device.SerialNumber, device.OSType, device.OSVersion, device.Role,
		device.Criticality, device.LocationID, device.ManagementIP, device.Metadata)
	return err
}

// DeleteDevice deletes a device
func (r *PostgresRepository) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM devices WHERE id = $1", id)
	return err
}

// ListDevices lists devices with optional filtering
func (r *PostgresRepository) ListDevices(ctx context.Context, filter DeviceFilter, limit, offset int) ([]*Device, int, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if filter.Role != "" {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argNum))
		args = append(args, filter.Role)
		argNum++
	}
	if filter.Criticality != "" {
		conditions = append(conditions, fmt.Sprintf("criticality = $%d", argNum))
		args = append(args, filter.Criticality)
		argNum++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, filter.Status)
		argNum++
	}
	if filter.TrustStatus != "" {
		conditions = append(conditions, fmt.Sprintf("trust_status = $%d", argNum))
		args = append(args, filter.TrustStatus)
		argNum++
	}
	if filter.LocationID != nil {
		conditions = append(conditions, fmt.Sprintf("location_id = $%d", argNum))
		args = append(args, *filter.LocationID)
		argNum++
	}
	if filter.Vendor != "" {
		conditions = append(conditions, fmt.Sprintf("vendor ILIKE $%d", argNum))
		args = append(args, "%"+filter.Vendor+"%")
		argNum++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(hostname ILIKE $%d OR vendor ILIKE $%d OR model ILIKE $%d)", argNum, argNum, argNum))
		args = append(args, "%"+filter.Search+"%")
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM devices %s", whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get devices
	query := fmt.Sprintf(`
		SELECT id, identity_id, hostname, vendor, model, serial_number, os_type, os_version,
			role, criticality, location_id, management_ip::text, status, trust_status, last_seen,
			current_config_sequence, metadata, created_at, updated_at
		FROM devices %s
		ORDER BY hostname
		LIMIT $%d OFFSET $%d
	`, whereClause, argNum, argNum+1)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		device := &Device{}
		var locationID sql.NullString
		err := rows.Scan(
			&device.ID, &device.IdentityID, &device.Hostname, &device.Vendor, &device.Model,
			&device.SerialNumber, &device.OSType, &device.OSVersion,
			&device.Role, &device.Criticality, &locationID, &device.ManagementIP,
			&device.Status, &device.TrustStatus, &device.LastSeen,
			&device.ConfigSequence, &device.Metadata, &device.CreatedAt, &device.UpdatedAt)
		if err != nil {
			return nil, 0, err
		}
		if locationID.Valid {
			locID, _ := uuid.Parse(locationID.String)
			device.LocationID = &locID
		}
		devices = append(devices, device)
	}

	return devices, total, nil
}

// UpdateDeviceStatus updates device status
func (r *PostgresRepository) UpdateDeviceStatus(ctx context.Context, id uuid.UUID, status DeviceStatus) error {
	_, err := r.pool.Exec(ctx, "UPDATE devices SET status = $2, updated_at = NOW() WHERE id = $1", id, status)
	return err
}

// UpdateDeviceTrustStatus updates device trust status
func (r *PostgresRepository) UpdateDeviceTrustStatus(ctx context.Context, id uuid.UUID, status TrustStatus) error {
	_, err := r.pool.Exec(ctx, "UPDATE devices SET trust_status = $2, updated_at = NOW() WHERE id = $1", id, status)
	return err
}

// Location operations

// CreateLocation creates a new location
func (r *PostgresRepository) CreateLocation(ctx context.Context, location *Location) error {
	query := `INSERT INTO locations (id, name, type, parent_id, address, metadata) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.pool.Exec(ctx, query, location.ID, location.Name, location.Type, location.ParentID, location.Address, location.Metadata)
	return err
}

// GetLocation retrieves a location by ID
func (r *PostgresRepository) GetLocation(ctx context.Context, id uuid.UUID) (*Location, error) {
	query := `SELECT id, name, type, parent_id, address, metadata FROM locations WHERE id = $1`
	location := &Location{}
	var parentID sql.NullString
	err := r.pool.QueryRow(ctx, query, id).Scan(&location.ID, &location.Name, &location.Type, &parentID, &location.Address, &location.Metadata)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	if parentID.Valid {
		pID, _ := uuid.Parse(parentID.String)
		location.ParentID = &pID
	}
	return location, nil
}

// UpdateLocation updates a location
func (r *PostgresRepository) UpdateLocation(ctx context.Context, location *Location) error {
	query := `UPDATE locations SET name = $2, type = $3, parent_id = $4, address = $5, metadata = $6 WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, location.ID, location.Name, location.Type, location.ParentID, location.Address, location.Metadata)
	return err
}

// DeleteLocation deletes a location
func (r *PostgresRepository) DeleteLocation(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM locations WHERE id = $1", id)
	return err
}

// ListLocations lists locations
func (r *PostgresRepository) ListLocations(ctx context.Context, parentID *uuid.UUID) ([]*Location, error) {
	var query string
	var args []interface{}
	if parentID != nil {
		query = `SELECT id, name, type, parent_id, address, metadata FROM locations WHERE parent_id = $1 ORDER BY name`
		args = append(args, *parentID)
	} else {
		query = `SELECT id, name, type, parent_id, address, metadata FROM locations ORDER BY name`
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locations []*Location
	for rows.Next() {
		location := &Location{}
		var pID sql.NullString
		if err := rows.Scan(&location.ID, &location.Name, &location.Type, &pID, &location.Address, &location.Metadata); err != nil {
			return nil, err
		}
		if pID.Valid {
			parentID, _ := uuid.Parse(pID.String)
			location.ParentID = &parentID
		}
		locations = append(locations, location)
	}
	return locations, nil
}

// Interface operations

// CreateInterface creates a new interface
func (r *PostgresRepository) CreateInterface(ctx context.Context, iface *Interface) error {
	return nil // Not implemented yet
}

// GetInterface retrieves an interface by ID
func (r *PostgresRepository) GetInterface(ctx context.Context, id uuid.UUID) (*Interface, error) {
	return nil, ErrDeviceNotFound // Not implemented yet
}

// ListInterfaces lists interfaces for a device
func (r *PostgresRepository) ListInterfaces(ctx context.Context, deviceID uuid.UUID) ([]*Interface, error) {
	return nil, nil // Not implemented yet
}

// UpdateInterface updates an interface
func (r *PostgresRepository) UpdateInterface(ctx context.Context, iface *Interface) error {
	return nil // Not implemented yet
}

// DeleteInterface deletes an interface
func (r *PostgresRepository) DeleteInterface(ctx context.Context, id uuid.UUID) error {
	return nil // Not implemented yet
}

// GetDeviceStats returns device statistics
func (r *PostgresRepository) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	stats := &DeviceStats{}
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'online') as online,
			COUNT(*) FILTER (WHERE status = 'offline') as offline,
			COUNT(*) FILTER (WHERE trust_status = 'quarantined') as quarantined,
			COUNT(*) FILTER (WHERE status = 'maintenance') as maintenance,
			COUNT(*) FILTER (WHERE status = 'unknown') as unknown
		FROM devices
	`
	err := r.pool.QueryRow(ctx, query).Scan(&stats.Total, &stats.Online, &stats.Offline, &stats.Quarantined, &stats.Maintenance, &stats.Unknown)
	return stats, err
}
