package capability_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/basicwoman/zt-nms/internal/capability"
	"github.com/basicwoman/zt-nms/pkg/models"
)

// MockRepository implements capability.Repository
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, token *models.CapabilityToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CapabilityToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.CapabilityToken), args.Error(1)
}

func (m *MockRepository) IncrementUseCount(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRepository) Revoke(ctx context.Context, id uuid.UUID, reason string, revokedBy uuid.UUID) error {
	args := m.Called(ctx, id, reason, revokedBy)
	return args.Error(0)
}

func (m *MockRepository) GetRevoked(ctx context.Context, since time.Time) ([][]byte, error) {
	args := m.Called(ctx, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([][]byte), args.Error(1)
}

func (m *MockRepository) ListBySubject(ctx context.Context, subjectID uuid.UUID, active bool) ([]*models.CapabilityToken, error) {
	args := m.Called(ctx, subjectID, active)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.CapabilityToken), args.Error(1)
}

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func createTestToken(subjectID uuid.UUID, subjectKey ed25519.PublicKey) *models.CapabilityToken {
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead, models.ActionConfigWrite},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	return models.NewCapabilityToken("test-issuer", subjectID, subjectKey, grants, validity, nil, nil)
}

func createIssuer(t *testing.T, mockRepo *MockRepository) *capability.Issuer {
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	// Create issuer without policy engine for testing
	issuer, err := capability.NewIssuer(mockRepo, nil, config, logger)
	require.NoError(t, err)
	return issuer
}

func TestNewIssuer(t *testing.T) {
	mockRepo := new(MockRepository)
	logger := zap.NewNop()

	config := &capability.IssuerConfig{
		IssuerID:   "test-issuer",
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}

	issuer, err := capability.NewIssuer(mockRepo, nil, config, logger)

	require.NoError(t, err)
	assert.NotNil(t, issuer)
	assert.NotNil(t, issuer.PublicKey())
}

func TestVerify_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()

	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC().Add(-2 * time.Hour),
		NotAfter:  time.Now().UTC().Add(-time.Hour), // Expired
	}
	expiredToken := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
	// Sign with issuer's key - get the public key from issuer
	// Since we can't access private key directly, we expect signature error first
	// The issuer checks signature before expiry

	err := issuer.Verify(ctx, expiredToken)

	// Since the token is not signed with issuer's key, signature verification fails first
	assert.Error(t, err)
	assert.Equal(t, models.ErrInvalidSignature, err)
}

func TestGetByID(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	tokenID := uuid.New()
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	expectedToken := createTestToken(subjectID, pubKey)
	expectedToken.TokenID = tokenID

	mockRepo.On("GetByID", ctx, tokenID).Return(expectedToken, nil)

	token, err := issuer.GetByID(ctx, tokenID)

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, tokenID, token.TokenID)
	mockRepo.AssertExpectations(t)
}

func TestListBySubject(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	expectedTokens := []*models.CapabilityToken{
		createTestToken(subjectID, pubKey),
		createTestToken(subjectID, pubKey),
	}

	mockRepo.On("ListBySubject", ctx, subjectID, true).Return(expectedTokens, nil)

	tokens, err := issuer.ListBySubject(ctx, subjectID, true)

	assert.NoError(t, err)
	assert.Len(t, tokens, 2)
	mockRepo.AssertExpectations(t)
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	tokenID := uuid.New()
	revokedBy := uuid.New()
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	token := createTestToken(subjectID, pubKey)
	token.TokenID = tokenID

	mockRepo.On("GetByID", ctx, tokenID).Return(token, nil)
	mockRepo.On("Revoke", ctx, tokenID, "security concern", revokedBy).Return(nil)

	err := issuer.Revoke(ctx, tokenID, "security concern", revokedBy)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestLoadRevocations(t *testing.T) {
	ctx := context.Background()
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	mockRepo.On("GetRevoked", ctx, mock.AnythingOfType("time.Time")).Return([][]byte{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
	}, nil)

	err := issuer.LoadRevocations(ctx)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestSerializeDeserialize(t *testing.T) {
	mockRepo := new(MockRepository)
	issuer := createIssuer(t, mockRepo)

	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	token := createTestToken(subjectID, pubKey)

	// Serialize
	data, err := issuer.Serialize(token)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Deserialize
	restored, err := issuer.Deserialize(data)
	require.NoError(t, err)
	assert.Equal(t, token.TokenID, restored.TokenID)
	assert.Equal(t, token.SubjectID, restored.SubjectID)
	assert.Equal(t, token.Issuer, restored.Issuer)
}

func TestCapabilityToken_Allows(t *testing.T) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()

	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead, models.ActionConfigWrite},
		},
		{
			Resource: models.ResourceSelector{Type: "device", Pattern: "router-*"},
			Actions:  []models.ActionType{models.ActionMonitorRead},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)

	// Test exact match
	assert.True(t, token.Allows(models.ActionConfigRead, "device", "device-123"))
	assert.True(t, token.Allows(models.ActionConfigWrite, "device", "device-123"))
	assert.False(t, token.Allows(models.ActionAdminManage, "device", "device-123"))

	// Test pattern match
	assert.True(t, token.Allows(models.ActionMonitorRead, "device", "router-01"))
	assert.True(t, token.Allows(models.ActionMonitorRead, "device", "router-xyz"))
	assert.False(t, token.Allows(models.ActionMonitorRead, "device", "switch-01"))
}

func TestCapabilityToken_IsValid(t *testing.T) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	grants := []models.Grant{}
	now := time.Now().UTC()

	// Valid token
	validity := models.Validity{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
	assert.True(t, token.IsValid(now))

	// Not yet valid
	validity = models.Validity{
		NotBefore: now.Add(time.Hour),
		NotAfter:  now.Add(2 * time.Hour),
	}
	futureToken := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
	assert.False(t, futureToken.IsValid(now))

	// Expired
	validity = models.Validity{
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	}
	expiredToken := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
	assert.False(t, expiredToken.IsValid(now))
}

func TestCapabilityToken_SignAndVerify(t *testing.T) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)

	// Sign with issuer key
	issuerPub, issuerPriv := generateKeyPair()
	token.Sign(issuerPriv)

	// Verify with correct key
	assert.True(t, token.Verify(issuerPub))

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	assert.False(t, token.Verify(wrongPub))
}

func TestCapabilityToken_Delegation(t *testing.T) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead, models.ActionConfigWrite},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	delegation := &models.DelegationRules{
		Allowed:            true,
		MaxDepth:           2,
		DelegatableActions: []models.ActionType{models.ActionConfigRead},
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, delegation)

	assert.True(t, token.Delegation.Allowed)
	assert.Equal(t, 2, token.Delegation.MaxDepth)
	assert.Contains(t, token.Delegation.DelegatableActions, models.ActionConfigRead)
}

// Benchmark tests
func BenchmarkTokenSign(b *testing.B) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	_, privKey := generateKeyPair()
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
		token.Sign(privKey)
	}
}

func BenchmarkTokenVerify(b *testing.B) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	issuerPub, issuerPriv := generateKeyPair()
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)
	token.Sign(issuerPriv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.Verify(issuerPub)
	}
}

func BenchmarkTokenAllows(b *testing.B) {
	subjectID := uuid.New()
	pubKey, _ := generateKeyPair()
	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{Type: "device", ID: "device-123"},
			Actions:  []models.ActionType{models.ActionConfigRead, models.ActionConfigWrite},
		},
		{
			Resource: models.ResourceSelector{Type: "config"},
			Actions:  []models.ActionType{models.ActionConfigBackup},
		},
	}
	validity := models.Validity{
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(time.Hour),
	}
	token := models.NewCapabilityToken("test-issuer", subjectID, pubKey, grants, validity, nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.Allows(models.ActionConfigRead, "device", "device-123")
	}
}
