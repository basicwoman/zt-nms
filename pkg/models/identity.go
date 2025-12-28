// Package models contains core data types for ZT-NMS
package models

import (
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// IdentityType represents the type of identity
type IdentityType string

const (
	IdentityTypeOperator IdentityType = "operator"
	IdentityTypeDevice   IdentityType = "device"
	IdentityTypeService  IdentityType = "service"
)

// IdentityStatus represents the status of an identity
type IdentityStatus string

const (
	IdentityStatusActive    IdentityStatus = "active"
	IdentityStatusSuspended IdentityStatus = "suspended"
	IdentityStatusRevoked   IdentityStatus = "revoked"
)

// Identity represents a cryptographic identity in the system
type Identity struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	Type        IdentityType           `json:"type" db:"type"`
	Attributes  map[string]interface{} `json:"attributes" db:"attributes"`
	PublicKey   ed25519.PublicKey      `json:"public_key" db:"public_key"`
	Certificate []byte                 `json:"certificate,omitempty" db:"certificate"`
	Status      IdentityStatus         `json:"status" db:"status"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
}

// OperatorAttributes contains attributes specific to operators
type OperatorAttributes struct {
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	Groups         []string `json:"groups"`
	Certifications []string `json:"certifications,omitempty"`
	ClearanceLevel int      `json:"clearance_level"`
	MFAEnabled     bool     `json:"mfa_enabled"`
}

// DeviceAttributes contains attributes specific to network devices
type DeviceAttributes struct {
	Hostname     string `json:"hostname"`
	Vendor       string `json:"vendor"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version"`
	Role         string `json:"role"`
	Criticality  string `json:"criticality"`
	LocationID   string `json:"location_id"`
	ManagementIP string `json:"management_ip"`
}

// ServiceAttributes contains attributes specific to service accounts
type ServiceAttributes struct {
	Name              string   `json:"name"`
	Owner             string   `json:"owner"`
	Purpose           string   `json:"purpose"`
	AllowedOperations []string `json:"allowed_operations"`
	SourceIPs         []string `json:"source_ips,omitempty"`
	MaxOpsPerHour     int      `json:"max_ops_per_hour,omitempty"`
}

// GetOperatorAttributes extracts operator attributes from identity
func (i *Identity) GetOperatorAttributes() (*OperatorAttributes, error) {
	if i.Type != IdentityTypeOperator {
		return nil, ErrInvalidIdentityType
	}
	data, err := json.Marshal(i.Attributes)
	if err != nil {
		return nil, err
	}
	var attrs OperatorAttributes
	if err := json.Unmarshal(data, &attrs); err != nil {
		return nil, err
	}
	return &attrs, nil
}

// GetDeviceAttributes extracts device attributes from identity
func (i *Identity) GetDeviceAttributes() (*DeviceAttributes, error) {
	if i.Type != IdentityTypeDevice {
		return nil, ErrInvalidIdentityType
	}
	data, err := json.Marshal(i.Attributes)
	if err != nil {
		return nil, err
	}
	var attrs DeviceAttributes
	if err := json.Unmarshal(data, &attrs); err != nil {
		return nil, err
	}
	return &attrs, nil
}

// GetServiceAttributes extracts service attributes from identity
func (i *Identity) GetServiceAttributes() (*ServiceAttributes, error) {
	if i.Type != IdentityTypeService {
		return nil, ErrInvalidIdentityType
	}
	data, err := json.Marshal(i.Attributes)
	if err != nil {
		return nil, err
	}
	var attrs ServiceAttributes
	if err := json.Unmarshal(data, &attrs); err != nil {
		return nil, err
	}
	return &attrs, nil
}

// NewOperatorIdentity creates a new operator identity
func NewOperatorIdentity(attrs OperatorAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) *Identity {
	attrsMap := make(map[string]interface{})
	data, _ := json.Marshal(attrs)
	json.Unmarshal(data, &attrsMap)

	return &Identity{
		ID:         uuid.New(),
		Type:       IdentityTypeOperator,
		Attributes: attrsMap,
		PublicKey:  publicKey,
		Status:     IdentityStatusActive,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
		CreatedBy:  createdBy,
	}
}

// NewDeviceIdentity creates a new device identity
func NewDeviceIdentity(attrs DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) *Identity {
	attrsMap := make(map[string]interface{})
	data, _ := json.Marshal(attrs)
	json.Unmarshal(data, &attrsMap)

	return &Identity{
		ID:         uuid.New(),
		Type:       IdentityTypeDevice,
		Attributes: attrsMap,
		PublicKey:  publicKey,
		Status:     IdentityStatusActive,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
		CreatedBy:  createdBy,
	}
}

// NewServiceIdentity creates a new service identity
func NewServiceIdentity(attrs ServiceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) *Identity {
	attrsMap := make(map[string]interface{})
	data, _ := json.Marshal(attrs)
	json.Unmarshal(data, &attrsMap)

	return &Identity{
		ID:         uuid.New(),
		Type:       IdentityTypeService,
		Attributes: attrsMap,
		PublicKey:  publicKey,
		Status:     IdentityStatusActive,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
		CreatedBy:  createdBy,
	}
}
