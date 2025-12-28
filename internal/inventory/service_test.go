package inventory

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockRepository is a mock implementation of Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateDevice(ctx context.Context, device *Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockRepository) GetDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Device), args.Error(1)
}

func (m *MockRepository) GetDeviceByHostname(ctx context.Context, hostname string) (*Device, error) {
	args := m.Called(ctx, hostname)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Device), args.Error(1)
}

func (m *MockRepository) GetDeviceByIP(ctx context.Context, ip string) (*Device, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Device), args.Error(1)
}

func (m *MockRepository) UpdateDevice(ctx context.Context, device *Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockRepository) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListDevices(ctx context.Context, filter DeviceFilter, limit, offset int) ([]*Device, int, error) {
	args := m.Called(ctx, filter, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*Device), args.Int(1), args.Error(2)
}

func (m *MockRepository) UpdateDeviceStatus(ctx context.Context, id uuid.UUID, status DeviceStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRepository) UpdateDeviceTrustStatus(ctx context.Context, id uuid.UUID, status TrustStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockRepository) CreateLocation(ctx context.Context, location *Location) error {
	args := m.Called(ctx, location)
	return args.Error(0)
}

func (m *MockRepository) GetLocation(ctx context.Context, id uuid.UUID) (*Location, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Location), args.Error(1)
}

func (m *MockRepository) UpdateLocation(ctx context.Context, location *Location) error {
	args := m.Called(ctx, location)
	return args.Error(0)
}

func (m *MockRepository) DeleteLocation(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) ListLocations(ctx context.Context, parentID *uuid.UUID) ([]*Location, error) {
	args := m.Called(ctx, parentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Location), args.Error(1)
}

func (m *MockRepository) CreateInterface(ctx context.Context, iface *Interface) error {
	args := m.Called(ctx, iface)
	return args.Error(0)
}

func (m *MockRepository) GetInterface(ctx context.Context, id uuid.UUID) (*Interface, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Interface), args.Error(1)
}

func (m *MockRepository) ListInterfaces(ctx context.Context, deviceID uuid.UUID) ([]*Interface, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Interface), args.Error(1)
}

func (m *MockRepository) UpdateInterface(ctx context.Context, iface *Interface) error {
	args := m.Called(ctx, iface)
	return args.Error(0)
}

func (m *MockRepository) DeleteInterface(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) GetDeviceStats(ctx context.Context) (*DeviceStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DeviceStats), args.Error(1)
}

// MockIdentityService is a mock implementation of IdentityService
type MockIdentityService struct {
	mock.Mock
}

func (m *MockIdentityService) CreateDevice(ctx context.Context, attrs models.DeviceAttributes, publicKey ed25519.PublicKey, createdBy *uuid.UUID) (*models.Identity, error) {
	args := m.Called(ctx, attrs, publicKey, createdBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockIdentityService) GetByID(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Identity), args.Error(1)
}

func (m *MockIdentityService) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error {
	args := m.Called(ctx, id, revokedBy, reason)
	return args.Error(0)
}

// MockAuditLogger is a mock implementation of AuditLogger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogDeviceEvent(ctx context.Context, eventType models.AuditEventType, deviceID uuid.UUID, actor *uuid.UUID, result models.AuditResult, details map[string]interface{}) error {
	args := m.Called(ctx, eventType, deviceID, actor, result, details)
	return args.Error(0)
}

func TestDevice(t *testing.T) {
	now := time.Now()
	device := &Device{
		ID:           uuid.New(),
		IdentityID:   uuid.New(),
		Hostname:     "router-01",
		Vendor:       "Cisco",
		Model:        "ISR 4431",
		SerialNumber: "SN12345",
		OSType:       "IOS-XE",
		OSVersion:    "17.3.4",
		Role:         DeviceRoleCore,
		Criticality:  DeviceCriticalityCritical,
		ManagementIP: "10.0.0.1",
		Status:       DeviceStatusOnline,
		TrustStatus:  TrustStatusVerified,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	assert.NotEqual(t, uuid.Nil, device.ID)
	assert.Equal(t, "router-01", device.Hostname)
	assert.Equal(t, DeviceRoleCore, device.Role)
	assert.Equal(t, DeviceCriticalityCritical, device.Criticality)
	assert.Equal(t, DeviceStatusOnline, device.Status)
	assert.Equal(t, TrustStatusVerified, device.TrustStatus)
}

func TestDeviceRoles(t *testing.T) {
	roles := []DeviceRole{
		DeviceRoleCore,
		DeviceRoleDistribution,
		DeviceRoleAccess,
		DeviceRoleEdge,
		DeviceRoleFirewall,
		DeviceRoleLoadBalancer,
		DeviceRoleWLC,
		DeviceRoleAP,
	}

	for _, role := range roles {
		assert.NotEmpty(t, string(role))
	}
}

func TestDeviceCriticality(t *testing.T) {
	levels := []DeviceCriticality{
		DeviceCriticalityCritical,
		DeviceCriticalityHigh,
		DeviceCriticalityMedium,
		DeviceCriticalityLow,
	}

	for _, level := range levels {
		assert.NotEmpty(t, string(level))
	}
}

func TestDeviceStatus(t *testing.T) {
	statuses := []DeviceStatus{
		DeviceStatusOnline,
		DeviceStatusOffline,
		DeviceStatusQuarantined,
		DeviceStatusMaintenance,
		DeviceStatusUnknown,
	}

	for _, status := range statuses {
		assert.NotEmpty(t, string(status))
	}
}

func TestTrustStatus(t *testing.T) {
	statuses := []TrustStatus{
		TrustStatusVerified,
		TrustStatusUntrusted,
		TrustStatusPending,
		TrustStatusUnknown,
	}

	for _, status := range statuses {
		assert.NotEmpty(t, string(status))
	}
}

func TestLocation(t *testing.T) {
	now := time.Now()
	parentID := uuid.New()
	loc := &Location{
		ID:       uuid.New(),
		Name:     "DC-1",
		Type:     LocationTypeDatacenter,
		ParentID: &parentID,
		Address: map[string]string{
			"city":    "New York",
			"country": "USA",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.NotEqual(t, uuid.Nil, loc.ID)
	assert.Equal(t, "DC-1", loc.Name)
	assert.Equal(t, LocationTypeDatacenter, loc.Type)
	assert.NotNil(t, loc.ParentID)
}

func TestLocationTypes(t *testing.T) {
	types := []LocationType{
		LocationTypeDatacenter,
		LocationTypeOffice,
		LocationTypePOP,
		LocationTypeBranch,
		LocationTypeRack,
	}

	for _, lt := range types {
		assert.NotEmpty(t, string(lt))
	}
}

func TestInterface(t *testing.T) {
	iface := &Interface{
		ID:          uuid.New(),
		DeviceID:    uuid.New(),
		Name:        "GigabitEthernet0/0/0",
		Type:        InterfaceTypeEthernet,
		MACAddress:  "00:1A:2B:3C:4D:5E",
		Enabled:     true,
		Description: "Uplink to core",
		Speed:       1000000000,
		MTU:         1500,
	}

	assert.NotEqual(t, uuid.Nil, iface.ID)
	assert.Equal(t, "GigabitEthernet0/0/0", iface.Name)
	assert.Equal(t, InterfaceTypeEthernet, iface.Type)
	assert.True(t, iface.Enabled)
}

func TestInterfaceTypes(t *testing.T) {
	types := []InterfaceType{
		InterfaceTypeEthernet,
		InterfaceTypeLoopback,
		InterfaceTypeVLAN,
		InterfaceTypeTunnel,
		InterfaceTypeBond,
	}

	for _, it := range types {
		assert.NotEmpty(t, string(it))
	}
}

func TestIPAddress(t *testing.T) {
	ifaceID := uuid.New()
	ip := &IPAddress{
		ID:          uuid.New(),
		Address:     "10.0.0.1/24",
		InterfaceID: &ifaceID,
		Status:      "active",
		DNSName:     "router-01.example.com",
		Description: "Management IP",
	}

	assert.NotEqual(t, uuid.Nil, ip.ID)
	assert.Equal(t, "10.0.0.1/24", ip.Address)
	assert.Equal(t, "active", ip.Status)
}

func TestDeviceFilter(t *testing.T) {
	locID := uuid.New()
	filter := DeviceFilter{
		Role:        DeviceRoleCore,
		Criticality: DeviceCriticalityHigh,
		Status:      DeviceStatusOnline,
		TrustStatus: TrustStatusVerified,
		LocationID:  &locID,
		Vendor:      "Cisco",
		Search:      "router",
	}

	assert.Equal(t, DeviceRoleCore, filter.Role)
	assert.Equal(t, "Cisco", filter.Vendor)
	assert.Equal(t, "router", filter.Search)
}

func TestDeviceStats(t *testing.T) {
	stats := &DeviceStats{
		Total:       100,
		Online:      80,
		Offline:     10,
		Quarantined: 5,
		Maintenance: 3,
		Unknown:     2,
	}

	assert.Equal(t, 100, stats.Total)
	assert.Equal(t, 80, stats.Online)
	assert.Equal(t, 10, stats.Offline)
}

func TestErrors(t *testing.T) {
	assert.Error(t, ErrDeviceNotFound)
	assert.Error(t, ErrDeviceExists)
	assert.Error(t, ErrLocationNotFound)
	assert.Error(t, ErrInterfaceNotFound)

	assert.Equal(t, "device not found", ErrDeviceNotFound.Error())
	assert.Equal(t, "device already exists", ErrDeviceExists.Error())
}

// ========== Service Tests ==========

func TestNewService(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)

	svc := NewService(mockRepo, mockIdentity, mockAudit, logger, nil)

	assert.NotNil(t, svc)
	assert.Equal(t, 5*time.Minute, svc.statusTimeout)
}

func TestNewService_WithConfig(t *testing.T) {
	logger := zap.NewNop()
	config := &Config{StatusTimeout: 10 * time.Minute}

	svc := NewService(nil, nil, nil, logger, config)

	assert.NotNil(t, svc)
	assert.Equal(t, 10*time.Minute, svc.statusTimeout)
}

func TestService_RegisterDevice_Success(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)
	mockAudit := new(MockAuditLogger)

	publicKey, _, _ := ed25519.GenerateKey(nil)
	registeredBy := uuid.New()

	// Hostname doesn't exist
	mockRepo.On("GetDeviceByHostname", mock.Anything, "router-01").Return(nil, ErrDeviceNotFound)

	// Identity created
	identity := &models.Identity{ID: uuid.New(), Type: models.IdentityTypeDevice}
	mockIdentity.On("CreateDevice", mock.Anything, mock.AnythingOfType("models.DeviceAttributes"), publicKey, &registeredBy).Return(identity, nil)

	// Device created
	mockRepo.On("CreateDevice", mock.Anything, mock.AnythingOfType("*inventory.Device")).Return(nil)

	// Audit logged
	mockAudit.On("LogDeviceEvent", mock.Anything, models.AuditEventDeviceRegister, mock.AnythingOfType("uuid.UUID"), &registeredBy, models.AuditResultSuccess, mock.Anything).Return(nil)

	svc := NewService(mockRepo, mockIdentity, mockAudit, logger, nil)

	req := &DeviceRegistrationRequest{
		Hostname:     "router-01",
		Vendor:       "Cisco",
		Model:        "ISR4431",
		ManagementIP: "10.0.0.1",
		Role:         DeviceRoleCore,
		Criticality:  DeviceCriticalityCritical,
	}

	device, err := svc.RegisterDevice(context.Background(), req, publicKey, &registeredBy)

	assert.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, "router-01", device.Hostname)
	assert.Equal(t, DeviceStatusUnknown, device.Status)
	assert.Equal(t, TrustStatusPending, device.TrustStatus)

	mockRepo.AssertExpectations(t)
	mockIdentity.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestService_RegisterDevice_AlreadyExists(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)

	publicKey, _, _ := ed25519.GenerateKey(nil)

	existingDevice := &Device{ID: uuid.New(), Hostname: "router-01"}
	mockRepo.On("GetDeviceByHostname", mock.Anything, "router-01").Return(existingDevice, nil)

	svc := NewService(mockRepo, mockIdentity, nil, logger, nil)

	req := &DeviceRegistrationRequest{
		Hostname:     "router-01",
		ManagementIP: "10.0.0.1",
	}

	device, err := svc.RegisterDevice(context.Background(), req, publicKey, nil)

	assert.Error(t, err)
	assert.Equal(t, ErrDeviceExists, err)
	assert.Nil(t, device)
}

func TestService_GetDevice(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	expectedDevice := &Device{ID: deviceID, Hostname: "router-01"}

	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(expectedDevice, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	device, err := svc.GetDevice(context.Background(), deviceID)

	assert.NoError(t, err)
	assert.Equal(t, expectedDevice, device)
	mockRepo.AssertExpectations(t)
}

func TestService_GetDevice_NotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(nil, ErrDeviceNotFound)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	device, err := svc.GetDevice(context.Background(), deviceID)

	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestService_GetDeviceByHostname(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	expectedDevice := &Device{ID: uuid.New(), Hostname: "router-01"}
	mockRepo.On("GetDeviceByHostname", mock.Anything, "router-01").Return(expectedDevice, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	device, err := svc.GetDeviceByHostname(context.Background(), "router-01")

	assert.NoError(t, err)
	assert.Equal(t, expectedDevice, device)
}

func TestService_UpdateDevice(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	existingDevice := &Device{
		ID:       deviceID,
		Hostname: "router-01",
		Vendor:   "Cisco",
	}

	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(existingDevice, nil)
	mockRepo.On("UpdateDevice", mock.Anything, mock.AnythingOfType("*inventory.Device")).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	req := &DeviceUpdateRequest{
		Hostname: "router-02",
		Vendor:   "Juniper",
	}

	device, err := svc.UpdateDevice(context.Background(), deviceID, req, nil)

	assert.NoError(t, err)
	assert.Equal(t, "router-02", device.Hostname)
	assert.Equal(t, "Juniper", device.Vendor)
	mockRepo.AssertExpectations(t)
}

func TestService_UpdateDevice_NotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(nil, ErrDeviceNotFound)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	device, err := svc.UpdateDevice(context.Background(), deviceID, &DeviceUpdateRequest{}, nil)

	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestService_DeleteDevice(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)

	deviceID := uuid.New()
	identityID := uuid.New()
	deletedBy := uuid.New()

	existingDevice := &Device{
		ID:         deviceID,
		IdentityID: identityID,
		Hostname:   "router-01",
	}

	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(existingDevice, nil)
	mockIdentity.On("Revoke", mock.Anything, identityID, deletedBy, "device deleted").Return(nil)
	mockRepo.On("DeleteDevice", mock.Anything, deviceID).Return(nil)

	svc := NewService(mockRepo, mockIdentity, nil, logger, nil)

	err := svc.DeleteDevice(context.Background(), deviceID, &deletedBy)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockIdentity.AssertExpectations(t)
}

func TestService_DeleteDevice_NotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(nil, ErrDeviceNotFound)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.DeleteDevice(context.Background(), deviceID, nil)

	assert.Error(t, err)
}

func TestService_ListDevices(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	devices := []*Device{
		{ID: uuid.New(), Hostname: "router-01"},
		{ID: uuid.New(), Hostname: "router-02"},
	}

	mockRepo.On("ListDevices", mock.Anything, DeviceFilter{}, 50, 0).Return(devices, 2, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	result, total, err := svc.ListDevices(context.Background(), DeviceFilter{}, 0, 0)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, 2, total)
}

func TestService_ListDevices_LimitCapping(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	mockRepo.On("ListDevices", mock.Anything, DeviceFilter{}, 1000, 0).Return([]*Device{}, 0, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	// Request 5000, should cap to 1000
	_, _, err := svc.ListDevices(context.Background(), DeviceFilter{}, 5000, 0)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestService_UpdateStatus(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("UpdateDeviceStatus", mock.Anything, deviceID, DeviceStatusOnline).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.UpdateStatus(context.Background(), deviceID, DeviceStatusOnline)

	assert.NoError(t, err)

	// Check in-memory status cache
	svc.statusMu.RLock()
	status, exists := svc.deviceStatuses[deviceID]
	svc.statusMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, DeviceStatusOnline, status)
}

func TestService_UpdateTrustStatus(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("UpdateDeviceTrustStatus", mock.Anything, deviceID, TrustStatusVerified).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.UpdateTrustStatus(context.Background(), deviceID, TrustStatusVerified)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestService_RecordHeartbeat(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	existingDevice := &Device{
		ID:       deviceID,
		Hostname: "router-01",
		Status:   DeviceStatusUnknown,
	}

	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(existingDevice, nil)
	mockRepo.On("UpdateDevice", mock.Anything, mock.AnythingOfType("*inventory.Device")).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.RecordHeartbeat(context.Background(), deviceID)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestService_RecordHeartbeat_DeviceNotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(nil, ErrDeviceNotFound)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.RecordHeartbeat(context.Background(), deviceID)

	assert.Error(t, err)
}

func TestService_GetDeviceStats(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	expectedStats := &DeviceStats{
		Total:   100,
		Online:  80,
		Offline: 20,
	}
	mockRepo.On("GetDeviceStats", mock.Anything).Return(expectedStats, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	stats, err := svc.GetDeviceStats(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, expectedStats, stats)
}

func TestService_CreateLocation(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	mockRepo.On("CreateLocation", mock.Anything, mock.AnythingOfType("*inventory.Location")).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	location := &Location{
		Name: "DC-1",
		Type: LocationTypeDatacenter,
	}

	err := svc.CreateLocation(context.Background(), location)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, location.ID)
	assert.False(t, location.CreatedAt.IsZero())
	mockRepo.AssertExpectations(t)
}

func TestService_GetLocation(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	locationID := uuid.New()
	expectedLocation := &Location{ID: locationID, Name: "DC-1"}
	mockRepo.On("GetLocation", mock.Anything, locationID).Return(expectedLocation, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	location, err := svc.GetLocation(context.Background(), locationID)

	assert.NoError(t, err)
	assert.Equal(t, expectedLocation, location)
}

func TestService_ListLocations(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	locations := []*Location{
		{ID: uuid.New(), Name: "DC-1"},
		{ID: uuid.New(), Name: "DC-2"},
	}
	mockRepo.On("ListLocations", mock.Anything, (*uuid.UUID)(nil)).Return(locations, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	result, err := svc.ListLocations(context.Background(), nil)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestService_GetDeviceInterfaces(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	interfaces := []*Interface{
		{ID: uuid.New(), Name: "Gi0/0"},
		{ID: uuid.New(), Name: "Gi0/1"},
	}
	mockRepo.On("ListInterfaces", mock.Anything, deviceID).Return(interfaces, nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	result, err := svc.GetDeviceInterfaces(context.Background(), deviceID)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestService_UpdateDeviceConfig(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	existingDevice := &Device{
		ID:             deviceID,
		Hostname:       "router-01",
		ConfigSequence: 0,
	}

	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(existingDevice, nil)
	mockRepo.On("UpdateDevice", mock.Anything, mock.AnythingOfType("*inventory.Device")).Return(nil)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	configHash := []byte("abc123")
	err := svc.UpdateDeviceConfig(context.Background(), deviceID, 5, configHash)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestService_UpdateDeviceConfig_DeviceNotFound(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)

	deviceID := uuid.New()
	mockRepo.On("GetDevice", mock.Anything, deviceID).Return(nil, ErrDeviceNotFound)

	svc := NewService(mockRepo, nil, nil, logger, nil)

	err := svc.UpdateDeviceConfig(context.Background(), deviceID, 5, []byte("hash"))

	assert.Error(t, err)
}

func TestIdentityServiceAdapter(t *testing.T) {
	mockSvc := new(MockIdentityService)
	adapter := NewIdentityServiceAdapter(mockSvc)

	assert.NotNil(t, adapter)

	// Test CreateDevice
	publicKey, _, _ := ed25519.GenerateKey(nil)
	identity := &models.Identity{ID: uuid.New()}
	mockSvc.On("CreateDevice", mock.Anything, mock.Anything, publicKey, (*uuid.UUID)(nil)).Return(identity, nil)

	result, err := adapter.CreateDevice(context.Background(), models.DeviceAttributes{}, publicKey, nil)
	assert.NoError(t, err)
	assert.Equal(t, identity, result)

	// Test GetByID
	mockSvc.On("GetByID", mock.Anything, identity.ID).Return(identity, nil)
	result2, err := adapter.GetByID(context.Background(), identity.ID)
	assert.NoError(t, err)
	assert.Equal(t, identity, result2)

	// Test Revoke
	revokedBy := uuid.New()
	mockSvc.On("Revoke", mock.Anything, identity.ID, revokedBy, "test").Return(nil)
	err = adapter.Revoke(context.Background(), identity.ID, revokedBy, "test")
	assert.NoError(t, err)

	mockSvc.AssertExpectations(t)
}

func TestDeviceRegistrationRequest(t *testing.T) {
	locationID := uuid.New()
	req := &DeviceRegistrationRequest{
		Hostname:     "router-01",
		Vendor:       "Cisco",
		Model:        "ISR4431",
		SerialNumber: "SN12345",
		OSType:       "IOS-XE",
		OSVersion:    "17.3.4",
		Role:         DeviceRoleCore,
		Criticality:  DeviceCriticalityCritical,
		LocationID:   &locationID,
		ManagementIP: "10.0.0.1",
		Metadata:     map[string]interface{}{"env": "prod"},
	}

	assert.Equal(t, "router-01", req.Hostname)
	assert.Equal(t, DeviceRoleCore, req.Role)
	assert.NotNil(t, req.LocationID)
}

func TestDeviceUpdateRequest(t *testing.T) {
	locationID := uuid.New()
	req := &DeviceUpdateRequest{
		Hostname:    "router-02",
		Vendor:      "Juniper",
		Model:       "MX104",
		OSVersion:   "20.4R1",
		Role:        DeviceRoleDistribution,
		Criticality: DeviceCriticalityHigh,
		LocationID:  &locationID,
		Metadata:    map[string]interface{}{"env": "staging"},
	}

	assert.Equal(t, "router-02", req.Hostname)
	assert.Equal(t, DeviceRoleDistribution, req.Role)
}

func TestService_RegisterDevice_IdentityCreationFails(t *testing.T) {
	logger := zap.NewNop()
	mockRepo := new(MockRepository)
	mockIdentity := new(MockIdentityService)

	publicKey, _, _ := ed25519.GenerateKey(nil)

	mockRepo.On("GetDeviceByHostname", mock.Anything, "router-01").Return(nil, ErrDeviceNotFound)
	mockIdentity.On("CreateDevice", mock.Anything, mock.Anything, publicKey, (*uuid.UUID)(nil)).Return(nil, errors.New("identity creation failed"))

	svc := NewService(mockRepo, mockIdentity, nil, logger, nil)

	req := &DeviceRegistrationRequest{
		Hostname:     "router-01",
		ManagementIP: "10.0.0.1",
	}

	device, err := svc.RegisterDevice(context.Background(), req, publicKey, nil)

	assert.Error(t, err)
	assert.Nil(t, device)
}
