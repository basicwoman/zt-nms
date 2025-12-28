package inventory

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

var (
	ErrDeviceNotFound    = errors.New("device not found")
	ErrDeviceExists      = errors.New("device already exists")
	ErrLocationNotFound  = errors.New("location not found")
	ErrInterfaceNotFound = errors.New("interface not found")
)

// Device represents a network device in the inventory
type Device struct {
	ID               uuid.UUID         `json:"id" db:"id"`
	IdentityID       uuid.UUID         `json:"identity_id" db:"identity_id"`
	Hostname         string            `json:"hostname" db:"hostname"`
	Vendor           string            `json:"vendor" db:"vendor"`
	Model            string            `json:"model" db:"model"`
	SerialNumber     string            `json:"serial_number" db:"serial_number"`
	OSType           string            `json:"os_type" db:"os_type"`
	OSVersion        string            `json:"os_version" db:"os_version"`
	Role             DeviceRole        `json:"role" db:"role"`
	Criticality      DeviceCriticality `json:"criticality" db:"criticality"`
	LocationID       *uuid.UUID        `json:"location_id,omitempty" db:"location_id"`
	ManagementIP     string            `json:"management_ip" db:"management_ip"`
	Status           DeviceStatus      `json:"status" db:"status"`
	TrustStatus      TrustStatus       `json:"trust_status" db:"trust_status"`
	LastSeen         *time.Time        `json:"last_seen,omitempty" db:"last_seen"`
	ConfigSequence   int64             `json:"config_sequence" db:"current_config_sequence"`
	ConfigHash       []byte            `json:"config_hash,omitempty" db:"current_config_hash"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" db:"updated_at"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// DeviceRole represents the role of a device
type DeviceRole string

const (
	DeviceRoleCore       DeviceRole = "core"
	DeviceRoleDistribution DeviceRole = "distribution"
	DeviceRoleAccess     DeviceRole = "access"
	DeviceRoleEdge       DeviceRole = "edge"
	DeviceRoleFirewall   DeviceRole = "firewall"
	DeviceRoleLoadBalancer DeviceRole = "loadbalancer"
	DeviceRoleWLC        DeviceRole = "wlc"
	DeviceRoleAP         DeviceRole = "ap"
)

// DeviceCriticality represents the criticality level
type DeviceCriticality string

const (
	DeviceCriticalityCritical DeviceCriticality = "critical"
	DeviceCriticalityHigh     DeviceCriticality = "high"
	DeviceCriticalityMedium   DeviceCriticality = "medium"
	DeviceCriticalityLow      DeviceCriticality = "low"
)

// DeviceStatus represents the operational status
type DeviceStatus string

const (
	DeviceStatusOnline      DeviceStatus = "online"
	DeviceStatusOffline     DeviceStatus = "offline"
	DeviceStatusQuarantined DeviceStatus = "quarantined"
	DeviceStatusMaintenance DeviceStatus = "maintenance"
	DeviceStatusUnknown     DeviceStatus = "unknown"
)

// TrustStatus represents the trust status
type TrustStatus string

const (
	TrustStatusVerified   TrustStatus = "verified"
	TrustStatusUntrusted  TrustStatus = "untrusted"
	TrustStatusPending    TrustStatus = "pending"
	TrustStatusUnknown    TrustStatus = "unknown"
)

// Location represents a physical location
type Location struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	Type      LocationType           `json:"type" db:"type"`
	ParentID  *uuid.UUID             `json:"parent_id,omitempty" db:"parent_id"`
	Address   map[string]string      `json:"address,omitempty" db:"address"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// LocationType represents the type of location
type LocationType string

const (
	LocationTypeDatacenter LocationType = "datacenter"
	LocationTypeOffice     LocationType = "office"
	LocationTypePOP        LocationType = "pop"
	LocationTypeBranch     LocationType = "branch"
	LocationTypeRack       LocationType = "rack"
)

// Interface represents a device interface
type Interface struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	DeviceID    uuid.UUID              `json:"device_id" db:"device_id"`
	Name        string                 `json:"name" db:"name"`
	Type        InterfaceType          `json:"type" db:"type"`
	MACAddress  string                 `json:"mac_address,omitempty" db:"mac_address"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	Description string                 `json:"description,omitempty" db:"description"`
	Speed       int64                  `json:"speed,omitempty" db:"speed"`
	MTU         int                    `json:"mtu,omitempty" db:"mtu"`
	IPs         []IPAddress            `json:"ips,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// InterfaceType represents interface type
type InterfaceType string

const (
	InterfaceTypeEthernet InterfaceType = "ethernet"
	InterfaceTypeLoopback InterfaceType = "loopback"
	InterfaceTypeVLAN     InterfaceType = "vlan"
	InterfaceTypeTunnel   InterfaceType = "tunnel"
	InterfaceTypeBond     InterfaceType = "bond"
)

// IPAddress represents an IP address assignment
type IPAddress struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Address     string     `json:"address" db:"address"`
	InterfaceID *uuid.UUID `json:"interface_id,omitempty" db:"interface_id"`
	VRFID       *uuid.UUID `json:"vrf_id,omitempty" db:"vrf_id"`
	Status      string     `json:"status" db:"status"`
	DNSName     string     `json:"dns_name,omitempty" db:"dns_name"`
	Description string     `json:"description,omitempty" db:"description"`
}

// Repository interface for inventory persistence
type Repository interface {
	// Devices
	CreateDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, id uuid.UUID) (*Device, error)
	GetDeviceByHostname(ctx context.Context, hostname string) (*Device, error)
	GetDeviceByIP(ctx context.Context, ip string) (*Device, error)
	UpdateDevice(ctx context.Context, device *Device) error
	DeleteDevice(ctx context.Context, id uuid.UUID) error
	ListDevices(ctx context.Context, filter DeviceFilter, limit, offset int) ([]*Device, int, error)
	UpdateDeviceStatus(ctx context.Context, id uuid.UUID, status DeviceStatus) error
	UpdateDeviceTrustStatus(ctx context.Context, id uuid.UUID, status TrustStatus) error

	// Locations
	CreateLocation(ctx context.Context, location *Location) error
	GetLocation(ctx context.Context, id uuid.UUID) (*Location, error)
	UpdateLocation(ctx context.Context, location *Location) error
	DeleteLocation(ctx context.Context, id uuid.UUID) error
	ListLocations(ctx context.Context, parentID *uuid.UUID) ([]*Location, error)

	// Interfaces
	CreateInterface(ctx context.Context, iface *Interface) error
	GetInterface(ctx context.Context, id uuid.UUID) (*Interface, error)
	ListInterfaces(ctx context.Context, deviceID uuid.UUID) ([]*Interface, error)
	UpdateInterface(ctx context.Context, iface *Interface) error
	DeleteInterface(ctx context.Context, id uuid.UUID) error

	// Stats
	GetDeviceStats(ctx context.Context) (*DeviceStats, error)
}

// DeviceFilter contains filter options
type DeviceFilter struct {
	Role        DeviceRole        `json:"role,omitempty"`
	Criticality DeviceCriticality `json:"criticality,omitempty"`
	Status      DeviceStatus      `json:"status,omitempty"`
	TrustStatus TrustStatus       `json:"trust_status,omitempty"`
	LocationID  *uuid.UUID        `json:"location_id,omitempty"`
	Vendor      string            `json:"vendor,omitempty"`
	Search      string            `json:"search,omitempty"`
}

// DeviceStats contains device statistics
type DeviceStats struct {
	Total       int `json:"total"`
	Online      int `json:"online"`
	Offline     int `json:"offline"`
	Quarantined int `json:"quarantined"`
	Maintenance int `json:"maintenance"`
	Unknown     int `json:"unknown"`
}

// IdentityService interface for identity operations
type IdentityService interface {
	CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error)
	Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error
}

// IdentityServiceAdapter adapts the identity.Service to IdentityService interface
type IdentityServiceAdapter struct {
	svc interface {
		CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error)
		GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error)
		Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error
	}
}

// NewIdentityServiceAdapter creates an adapter for the identity service
func NewIdentityServiceAdapter(svc interface {
	CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error)
	Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error
}) *IdentityServiceAdapter {
	return &IdentityServiceAdapter{svc: svc}
}

func (a *IdentityServiceAdapter) CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error) {
	return a.svc.CreateDevice(ctx, attrs, publicKey, createdBy)
}

func (a *IdentityServiceAdapter) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	return a.svc.GetByID(ctx, id)
}

func (a *IdentityServiceAdapter) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error {
	return a.svc.Revoke(ctx, id, revokedBy, reason)
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogDeviceEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, actor *uuid.UUID, result models.AuditResult, details map[string]interface{}) error
}

// Service provides inventory management operations
type Service struct {
	repo        Repository
	identitySvc IdentityService
	auditLog    AuditLogger
	logger      *zap.Logger

	// Status tracking
	deviceStatuses map[uuid.UUID]DeviceStatus
	statusMu       sync.RWMutex
	statusTimeout  time.Duration
}

// Config contains service configuration
type Config struct {
	StatusTimeout time.Duration
}

// NewService creates a new inventory service
func NewService(repo Repository, identitySvc IdentityService, auditLog AuditLogger, logger *zap.Logger, config *Config) *Service {
	statusTimeout := 5 * time.Minute
	if config != nil && config.StatusTimeout > 0 {
		statusTimeout = config.StatusTimeout
	}

	s := &Service{
		repo:           repo,
		identitySvc:    identitySvc,
		auditLog:       auditLog,
		logger:         logger,
		deviceStatuses: make(map[uuid.UUID]DeviceStatus),
		statusTimeout:  statusTimeout,
	}

	return s
}

// RegisterDevice registers a new device
func (s *Service) RegisterDevice(ctx context.Context, req *DeviceRegistrationRequest, publicKey ed25519.PublicKey, registeredBy *uuid.UUID) (*Device, error) {
	// Check if device already exists
	existing, err := s.repo.GetDeviceByHostname(ctx, req.Hostname)
	if err == nil && existing != nil {
		return nil, ErrDeviceExists
	}

	// Create identity for the device
	attrs := models.DeviceAttributes{
		Hostname:     req.Hostname,
		Vendor:       req.Vendor,
		Model:        req.Model,
		SerialNumber: req.SerialNumber,
		OSType:       req.OSType,
		OSVersion:    req.OSVersion,
		Role:         string(req.Role),
		Criticality:  string(req.Criticality),
		ManagementIP: req.ManagementIP,
	}

	identity, err := s.identitySvc.CreateDevice(ctx, attrs, publicKey, registeredBy)
	if err != nil {
		return nil, err
	}

	// Create device record
	device := &Device{
		ID:           uuid.New(),
		IdentityID:   identity.ID,
		Hostname:     req.Hostname,
		Vendor:       req.Vendor,
		Model:        req.Model,
		SerialNumber: req.SerialNumber,
		OSType:       req.OSType,
		OSVersion:    req.OSVersion,
		Role:         req.Role,
		Criticality:  req.Criticality,
		LocationID:   req.LocationID,
		ManagementIP: req.ManagementIP,
		Status:       DeviceStatusUnknown,
		TrustStatus:  TrustStatusPending,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		Metadata:     req.Metadata,
	}

	if err := s.repo.CreateDevice(ctx, device); err != nil {
		return nil, err
	}

	// Log audit event
	if s.auditLog != nil {
		s.auditLog.LogDeviceEvent(ctx, models.AuditEventDeviceRegister, device.ID, registeredBy, models.AuditResultSuccess, map[string]interface{}{
			"hostname":      device.Hostname,
			"vendor":        device.Vendor,
			"management_ip": device.ManagementIP,
		})
	}

	s.logger.Info("Device registered",
		zap.String("device_id", device.ID.String()),
		zap.String("hostname", device.Hostname),
	)

	return device, nil
}

// DeviceRegistrationRequest contains device registration data
type DeviceRegistrationRequest struct {
	Hostname     string                 `json:"hostname"`
	Vendor       string                 `json:"vendor"`
	Model        string                 `json:"model"`
	SerialNumber string                 `json:"serial_number"`
	OSType       string                 `json:"os_type"`
	OSVersion    string                 `json:"os_version"`
	Role         DeviceRole             `json:"role"`
	Criticality  DeviceCriticality      `json:"criticality"`
	LocationID   *uuid.UUID             `json:"location_id,omitempty"`
	ManagementIP string                 `json:"management_ip"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// GetDevice retrieves a device by ID
func (s *Service) GetDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	return s.repo.GetDevice(ctx, id)
}

// GetDeviceByHostname retrieves a device by hostname
func (s *Service) GetDeviceByHostname(ctx context.Context, hostname string) (*Device, error) {
	return s.repo.GetDeviceByHostname(ctx, hostname)
}

// UpdateDevice updates a device
func (s *Service) UpdateDevice(ctx context.Context, id uuid.UUID, req *DeviceUpdateRequest, updatedBy *uuid.UUID) (*Device, error) {
	device, err := s.repo.GetDevice(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Hostname != "" {
		device.Hostname = req.Hostname
	}
	if req.Vendor != "" {
		device.Vendor = req.Vendor
	}
	if req.Model != "" {
		device.Model = req.Model
	}
	if req.OSVersion != "" {
		device.OSVersion = req.OSVersion
	}
	if req.Role != "" {
		device.Role = req.Role
	}
	if req.Criticality != "" {
		device.Criticality = req.Criticality
	}
	if req.LocationID != nil {
		device.LocationID = req.LocationID
	}
	if req.Metadata != nil {
		device.Metadata = req.Metadata
	}
	device.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateDevice(ctx, device); err != nil {
		return nil, err
	}

	s.logger.Info("Device updated",
		zap.String("device_id", id.String()),
	)

	return device, nil
}

// DeviceUpdateRequest contains device update data
type DeviceUpdateRequest struct {
	Hostname    string                 `json:"hostname,omitempty"`
	Vendor      string                 `json:"vendor,omitempty"`
	Model       string                 `json:"model,omitempty"`
	OSVersion   string                 `json:"os_version,omitempty"`
	Role        DeviceRole             `json:"role,omitempty"`
	Criticality DeviceCriticality      `json:"criticality,omitempty"`
	LocationID  *uuid.UUID             `json:"location_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DeleteDevice deletes a device
func (s *Service) DeleteDevice(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	device, err := s.repo.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	// Revoke identity
	if s.identitySvc != nil && deletedBy != nil {
		if err := s.identitySvc.Revoke(ctx, device.IdentityID, *deletedBy, "device deleted"); err != nil {
			s.logger.Warn("Failed to revoke device identity", zap.Error(err))
		}
	}

	// Delete device
	if err := s.repo.DeleteDevice(ctx, id); err != nil {
		return err
	}

	s.logger.Info("Device deleted",
		zap.String("device_id", id.String()),
	)

	return nil
}

// ListDevices lists devices with filtering
func (s *Service) ListDevices(ctx context.Context, filter DeviceFilter, limit, offset int) ([]*Device, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.repo.ListDevices(ctx, filter, limit, offset)
}

// UpdateStatus updates device status
func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, status DeviceStatus) error {
	if err := s.repo.UpdateDeviceStatus(ctx, id, status); err != nil {
		return err
	}

	s.statusMu.Lock()
	s.deviceStatuses[id] = status
	s.statusMu.Unlock()

	return nil
}

// UpdateTrustStatus updates device trust status
func (s *Service) UpdateTrustStatus(ctx context.Context, id uuid.UUID, status TrustStatus) error {
	return s.repo.UpdateDeviceTrustStatus(ctx, id, status)
}

// RecordHeartbeat records a device heartbeat
func (s *Service) RecordHeartbeat(ctx context.Context, id uuid.UUID) error {
	device, err := s.repo.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	device.LastSeen = &now
	device.Status = DeviceStatusOnline
	device.UpdatedAt = now

	return s.repo.UpdateDevice(ctx, device)
}

// GetDeviceStats returns device statistics
func (s *Service) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	return s.repo.GetDeviceStats(ctx)
}

// CreateLocation creates a new location
func (s *Service) CreateLocation(ctx context.Context, location *Location) error {
	location.ID = uuid.New()
	location.CreatedAt = time.Now().UTC()
	location.UpdatedAt = time.Now().UTC()
	return s.repo.CreateLocation(ctx, location)
}

// GetLocation retrieves a location
func (s *Service) GetLocation(ctx context.Context, id uuid.UUID) (*Location, error) {
	return s.repo.GetLocation(ctx, id)
}

// ListLocations lists locations
func (s *Service) ListLocations(ctx context.Context, parentID *uuid.UUID) ([]*Location, error) {
	return s.repo.ListLocations(ctx, parentID)
}

// GetDeviceInterfaces retrieves interfaces for a device
func (s *Service) GetDeviceInterfaces(ctx context.Context, deviceID uuid.UUID) ([]*Interface, error) {
	return s.repo.ListInterfaces(ctx, deviceID)
}

// UpdateDeviceConfig updates device configuration hash
func (s *Service) UpdateDeviceConfig(ctx context.Context, id uuid.UUID, sequence int64, hash []byte) error {
	device, err := s.repo.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	device.ConfigSequence = sequence
	device.ConfigHash = hash
	device.UpdatedAt = time.Now().UTC()

	return s.repo.UpdateDevice(ctx, device)
}
