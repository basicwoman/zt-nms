package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceRole represents the role of a network device
type DeviceRole string

const (
	DeviceRoleCoreRouter       DeviceRole = "core-router"
	DeviceRoleDistributionRouter DeviceRole = "distribution-router"
	DeviceRoleEdgeRouter       DeviceRole = "edge-router"
	DeviceRoleCoreSwitch       DeviceRole = "core-switch"
	DeviceRoleAccessSwitch     DeviceRole = "access-switch"
	DeviceRoleFirewall         DeviceRole = "firewall"
	DeviceRoleLoadBalancer     DeviceRole = "load-balancer"
	DeviceRoleVPNGateway       DeviceRole = "vpn-gateway"
	DeviceRoleWirelessController DeviceRole = "wireless-controller"
	DeviceRoleAccessPoint      DeviceRole = "access-point"
)

// DeviceCriticality represents how critical a device is
type DeviceCriticality string

const (
	DeviceCriticalityLow      DeviceCriticality = "low"
	DeviceCriticalityMedium   DeviceCriticality = "medium"
	DeviceCriticalityHigh     DeviceCriticality = "high"
	DeviceCriticalityCritical DeviceCriticality = "critical"
)

// DeviceStatus represents the operational status of a device
type DeviceStatus string

const (
	DeviceStatusUnknown     DeviceStatus = "unknown"
	DeviceStatusOnline      DeviceStatus = "online"
	DeviceStatusOffline     DeviceStatus = "offline"
	DeviceStatusDegraded    DeviceStatus = "degraded"
	DeviceStatusMaintenance DeviceStatus = "maintenance"
)

// TrustStatus represents the trust status from attestation
type TrustStatus string

const (
	TrustStatusUnknown    TrustStatus = "unknown"
	TrustStatusVerified   TrustStatus = "verified"
	TrustStatusUntrusted  TrustStatus = "untrusted"
	TrustStatusQuarantined TrustStatus = "quarantined"
)

// ProtocolType represents the management protocol type
type ProtocolType string

const (
	ProtocolTypeSSH      ProtocolType = "ssh"
	ProtocolTypeNETCONF  ProtocolType = "netconf"
	ProtocolTypeRESTCONF ProtocolType = "restconf"
	ProtocolTypeSNMP     ProtocolType = "snmp"
	ProtocolTypeHTTPS    ProtocolType = "https"
	ProtocolTypeGNMI     ProtocolType = "gnmi"
)

// Device represents a network device
type Device struct {
	// Identity
	ID         uuid.UUID `json:"id" db:"id"`
	IdentityID uuid.UUID `json:"identity_id" db:"identity_id"` // Reference to Identity

	// Basic info
	Hostname     string `json:"hostname" db:"hostname"`
	Vendor       string `json:"vendor" db:"vendor"`
	Model        string `json:"model" db:"model"`
	SerialNumber string `json:"serial_number" db:"serial_number"`
	AssetTag     string `json:"asset_tag,omitempty" db:"asset_tag"`

	// Software
	OSType     string `json:"os_type" db:"os_type"`
	OSVersion  string `json:"os_version" db:"os_version"`
	FirmwareVersion string `json:"firmware_version,omitempty" db:"firmware_version"`

	// Classification
	Role        DeviceRole        `json:"role" db:"role"`
	Criticality DeviceCriticality `json:"criticality" db:"criticality"`
	Tags        []string          `json:"tags,omitempty" db:"tags"`

	// Location
	LocationID   *uuid.UUID `json:"location_id,omitempty" db:"location_id"`
	RackPosition string     `json:"rack_position,omitempty" db:"rack_position"`

	// Management
	ManagementIP      string         `json:"management_ip" db:"management_ip"`
	ManagementPort    int            `json:"management_port,omitempty" db:"management_port"`
	ManagementProtocol ProtocolType  `json:"management_protocol" db:"management_protocol"`
	SupportsAgent     bool           `json:"supports_agent" db:"supports_agent"`
	AgentVersion      string         `json:"agent_version,omitempty" db:"agent_version"`

	// Status
	Status      DeviceStatus `json:"status" db:"status"`
	TrustStatus TrustStatus  `json:"trust_status" db:"trust_status"`
	LastSeen    *time.Time   `json:"last_seen,omitempty" db:"last_seen"`
	LastAttestation *time.Time `json:"last_attestation,omitempty" db:"last_attestation"`

	// Configuration
	CurrentConfigSequence int64  `json:"current_config_sequence" db:"current_config_sequence"`
	CurrentConfigHash     []byte `json:"current_config_hash,omitempty" db:"current_config_hash"`
	StartupConfigHash     []byte `json:"startup_config_hash,omitempty" db:"startup_config_hash"`

	// Metadata
	Metadata  map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// DeviceCredentials represents encrypted device credentials
type DeviceCredentials struct {
	DeviceID       uuid.UUID    `json:"device_id" db:"device_id"`
	Protocol       ProtocolType `json:"protocol" db:"protocol"`
	EncryptedData  []byte       `json:"encrypted_data" db:"encrypted_data"` // Encrypted using device proxy key
	KeyVersion     int          `json:"key_version" db:"key_version"`
	LastRotated    time.Time    `json:"last_rotated" db:"last_rotated"`
	ExpiresAt      *time.Time   `json:"expires_at,omitempty" db:"expires_at"`
}

// DeviceInterface represents a network interface on a device
type DeviceInterface struct {
	ID          uuid.UUID `json:"id" db:"id"`
	DeviceID    uuid.UUID `json:"device_id" db:"device_id"`
	Name        string    `json:"name" db:"name"`
	Type        string    `json:"type" db:"type"`
	MACAddress  string    `json:"mac_address,omitempty" db:"mac_address"`
	Speed       int64     `json:"speed,omitempty" db:"speed"`
	MTU         int       `json:"mtu,omitempty" db:"mtu"`
	Enabled     bool      `json:"enabled" db:"enabled"`
	Description string    `json:"description,omitempty" db:"description"`
	VRF         string    `json:"vrf,omitempty" db:"vrf"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// IPAddress represents an IP address assigned to an interface
type IPAddress struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Address     string     `json:"address" db:"address"` // CIDR notation
	Version     int        `json:"version" db:"version"` // 4 or 6
	InterfaceID *uuid.UUID `json:"interface_id,omitempty" db:"interface_id"`
	DeviceID    *uuid.UUID `json:"device_id,omitempty" db:"device_id"`
	VRFID       *uuid.UUID `json:"vrf_id,omitempty" db:"vrf_id"`
	Status      string     `json:"status" db:"status"` // active, reserved, deprecated
	DNSName     string     `json:"dns_name,omitempty" db:"dns_name"`
	Description string     `json:"description,omitempty" db:"description"`
}

// Location represents a physical location
type Location struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Type        string     `json:"type" db:"type"` // datacenter, office, pop, closet
	ParentID    *uuid.UUID `json:"parent_id,omitempty" db:"parent_id"`
	Address     *Address   `json:"address,omitempty" db:"address"`
	Coordinates *GeoCoord  `json:"coordinates,omitempty" db:"coordinates"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// Address represents a physical address
type Address struct {
	Street1    string `json:"street1,omitempty"`
	Street2    string `json:"street2,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

// GeoCoord represents geographic coordinates
type GeoCoord struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// VRF represents a VRF instance
type VRF struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	RD          string    `json:"rd,omitempty" db:"rd"` // Route Distinguisher
	ImportRT    []string  `json:"import_rt,omitempty" db:"import_rt"`
	ExportRT    []string  `json:"export_rt,omitempty" db:"export_rt"`
	Description string    `json:"description,omitempty" db:"description"`
}

// DeviceGroup represents a group of devices
type DeviceGroup struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Name        string      `json:"name" db:"name"`
	Description string      `json:"description,omitempty" db:"description"`
	Type        string      `json:"type" db:"type"` // static, dynamic
	DeviceIDs   []uuid.UUID `json:"device_ids,omitempty" db:"device_ids"` // For static groups
	Query       *DeviceQuery `json:"query,omitempty" db:"query"` // For dynamic groups
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// DeviceQuery represents a query for dynamic device groups
type DeviceQuery struct {
	Roles        []DeviceRole        `json:"roles,omitempty"`
	Criticalities []DeviceCriticality `json:"criticalities,omitempty"`
	Vendors      []string            `json:"vendors,omitempty"`
	LocationIDs  []uuid.UUID         `json:"location_ids,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	Status       []DeviceStatus      `json:"status,omitempty"`
	TrustStatus  []TrustStatus       `json:"trust_status,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// DeviceConnection represents an active connection to a device
type DeviceConnection struct {
	ID             uuid.UUID    `json:"id"`
	DeviceID       uuid.UUID    `json:"device_id"`
	ProxyID        string       `json:"proxy_id"`
	Protocol       ProtocolType `json:"protocol"`
	Status         string       `json:"status"` // connected, disconnected, error
	ConnectedAt    time.Time    `json:"connected_at"`
	LastActivityAt time.Time    `json:"last_activity_at"`
	SessionID      uuid.UUID    `json:"session_id,omitempty"`
	OperatorID     *uuid.UUID   `json:"operator_id,omitempty"`
}

// DeviceHealthCheck represents a health check result
type DeviceHealthCheck struct {
	DeviceID    uuid.UUID `json:"device_id"`
	CheckTime   time.Time `json:"check_time"`
	Status      string    `json:"status"` // healthy, unhealthy, degraded
	Latency     int64     `json:"latency_ms"`
	CPUUsage    float64   `json:"cpu_usage,omitempty"`
	MemoryUsage float64   `json:"memory_usage,omitempty"`
	Uptime      int64     `json:"uptime_seconds,omitempty"`
	Errors      []string  `json:"errors,omitempty"`
}

// DeviceMetrics represents device metrics
type DeviceMetrics struct {
	DeviceID       uuid.UUID         `json:"device_id"`
	Timestamp      time.Time         `json:"timestamp"`
	CPUUsage       float64           `json:"cpu_usage"`
	MemoryTotal    int64             `json:"memory_total"`
	MemoryUsed     int64             `json:"memory_used"`
	InterfaceStats map[string]InterfaceStats `json:"interface_stats,omitempty"`
	BGPSessions    []BGPSessionStatus `json:"bgp_sessions,omitempty"`
	CustomMetrics  map[string]float64 `json:"custom_metrics,omitempty"`
}

// InterfaceStats represents interface statistics
type InterfaceStats struct {
	Name           string `json:"name"`
	BytesIn        int64  `json:"bytes_in"`
	BytesOut       int64  `json:"bytes_out"`
	PacketsIn      int64  `json:"packets_in"`
	PacketsOut     int64  `json:"packets_out"`
	ErrorsIn       int64  `json:"errors_in"`
	ErrorsOut      int64  `json:"errors_out"`
	OperStatus     string `json:"oper_status"`
	AdminStatus    string `json:"admin_status"`
}

// BGPSessionStatus represents BGP session status
type BGPSessionStatus struct {
	NeighborAddress string `json:"neighbor_address"`
	RemoteAS        uint32 `json:"remote_as"`
	State           string `json:"state"`
	PrefixesReceived int   `json:"prefixes_received"`
	PrefixesSent     int   `json:"prefixes_sent"`
	Uptime          int64  `json:"uptime_seconds"`
}

// NewDevice creates a new device
func NewDevice(
	hostname string,
	vendor string,
	model string,
	serialNumber string,
	managementIP string,
	protocol ProtocolType,
) *Device {
	return &Device{
		ID:                 uuid.New(),
		Hostname:           hostname,
		Vendor:             vendor,
		Model:              model,
		SerialNumber:       serialNumber,
		ManagementIP:       managementIP,
		ManagementProtocol: protocol,
		Status:             DeviceStatusUnknown,
		TrustStatus:        TrustStatusUnknown,
		Role:               DeviceRoleAccessSwitch, // default
		Criticality:        DeviceCriticalityMedium,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
}

// UpdateStatus updates the device status
func (d *Device) UpdateStatus(status DeviceStatus) {
	d.Status = status
	d.UpdatedAt = time.Now().UTC()
	if status == DeviceStatusOnline {
		now := time.Now().UTC()
		d.LastSeen = &now
	}
}

// UpdateTrustStatus updates the trust status
func (d *Device) UpdateTrustStatus(status TrustStatus) {
	d.TrustStatus = status
	d.UpdatedAt = time.Now().UTC()
	if status == TrustStatusVerified {
		now := time.Now().UTC()
		d.LastAttestation = &now
	}
}

// IsTrusted returns true if the device is trusted
func (d *Device) IsTrusted() bool {
	return d.TrustStatus == TrustStatusVerified
}

// IsOnline returns true if the device is online
func (d *Device) IsOnline() bool {
	return d.Status == DeviceStatusOnline
}

// IsCritical returns true if the device is critical
func (d *Device) IsCritical() bool {
	return d.Criticality == DeviceCriticalityCritical || d.Criticality == DeviceCriticalityHigh
}
