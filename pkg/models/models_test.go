package models_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basicwoman/zt-nms/pkg/models"
)

func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

// Identity tests
func TestNewOperatorIdentity(t *testing.T) {
	pubKey, _ := generateKeyPair()
	createdBy := uuid.New()

	attrs := models.OperatorAttributes{
		Username:    "testadmin",
		Email:       "admin@example.com",
		Groups:      []string{"network-admins", "security"},
		MFAEnabled:  true,
	}

	identity := models.NewOperatorIdentity(attrs, pubKey, &createdBy)

	assert.NotNil(t, identity)
	assert.NotEqual(t, uuid.Nil, identity.ID)
	assert.Equal(t, models.IdentityTypeOperator, identity.Type)
	assert.Equal(t, models.IdentityStatusActive, identity.Status)
	assert.Equal(t, pubKey, identity.PublicKey)
	assert.Equal(t, &createdBy, identity.CreatedBy)
}

func TestNewDeviceIdentity(t *testing.T) {
	pubKey, _ := generateKeyPair()

	attrs := models.DeviceAttributes{
		Hostname:     "switch-01.dc1",
		Vendor:       "Cisco",
		Model:        "Nexus 9000",
		SerialNumber: "SN12345",
		ManagementIP: "10.0.1.1",
		Role:         string(models.DeviceRoleCoreSwitch),
		Criticality:  string(models.DeviceCriticalityCritical),
	}

	identity := models.NewDeviceIdentity(attrs, pubKey, nil)

	assert.NotNil(t, identity)
	assert.Equal(t, models.IdentityTypeDevice, identity.Type)
	
	deviceAttrs, err := identity.GetDeviceAttributes()
	assert.NoError(t, err)
	assert.Equal(t, "switch-01.dc1", deviceAttrs.Hostname)
	assert.Equal(t, "Cisco", deviceAttrs.Vendor)
}

func TestNewServiceIdentity(t *testing.T) {
	pubKey, _ := generateKeyPair()

	attrs := models.ServiceAttributes{
		Name:              "config-manager",
		Owner:             "platform-team",
		Purpose:           "Configuration management service",
		AllowedOperations: []string{"config.read", "config.write"},
		MaxOpsPerHour:     1000,
	}

	identity := models.NewServiceIdentity(attrs, pubKey, nil)

	assert.NotNil(t, identity)
	assert.Equal(t, models.IdentityTypeService, identity.Type)
	
	svcAttrs, err := identity.GetServiceAttributes()
	assert.NoError(t, err)
	assert.Equal(t, "config-manager", svcAttrs.Name)
}

// Capability tests
func TestNewCapabilityToken(t *testing.T) {
	pubKey, _ := generateKeyPair()
	subjectID := uuid.New()

	grants := []models.Grant{
		{
			Resource: models.ResourceSelector{
				Type: "device",
				ID:   uuid.New().String(),
			},
			Actions: []models.ActionType{
				models.ActionConfigRead,
				models.ActionConfigWrite,
			},
		},
	}

	validity := models.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(8 * time.Hour),
		MaxUses:   100,
	}

	contextReqs := &models.ContextRequirements{
		MFARequired: true,
		SourceNetworks: []string{"10.0.0.0/8"},
	}

	token := models.NewCapabilityToken(
		"test-issuer",
		subjectID,
		pubKey,
		grants,
		validity,
		contextReqs,
		nil,
	)

	assert.NotNil(t, token)
	assert.Equal(t, uint8(1), token.Version)
	assert.NotEqual(t, uuid.Nil, token.TokenID)
	assert.Equal(t, subjectID, token.SubjectID)
	assert.Len(t, grants, 1)
}

func TestCapabilityToken_SignAndVerify(t *testing.T) {
	pubKey, privKey := generateKeyPair()
	subjectID := uuid.New()

	token := models.NewCapabilityToken(
		"test-issuer",
		subjectID,
		pubKey,
		[]models.Grant{},
		models.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		},
		nil,
		nil,
	)

	// Sign
	token.Sign(privKey)
	assert.NotEmpty(t, token.IssuerSignature)

	// Verify
	isValid := token.Verify(pubKey)
	assert.True(t, isValid)

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	isValid = token.Verify(wrongPub)
	assert.False(t, isValid)
}

func TestCapabilityToken_IsValid(t *testing.T) {
	pubKey, privKey := generateKeyPair()

	// Valid token
	validToken := models.NewCapabilityToken(
		"test-issuer",
		uuid.New(),
		pubKey,
		[]models.Grant{},
		models.Validity{
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		},
		nil,
		nil,
	)
	validToken.Sign(privKey)
	assert.True(t, validToken.IsValid(time.Now()))

	// Expired token
	expiredToken := models.NewCapabilityToken(
		"test-issuer",
		uuid.New(),
		pubKey,
		[]models.Grant{},
		models.Validity{
			NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter:  time.Now().Add(-time.Hour),
		},
		nil,
		nil,
	)
	expiredToken.Sign(privKey)
	assert.False(t, expiredToken.IsValid(time.Now()))

	// Not yet valid token
	futureToken := models.NewCapabilityToken(
		"test-issuer",
		uuid.New(),
		pubKey,
		[]models.Grant{},
		models.Validity{
			NotBefore: time.Now().Add(time.Hour),
			NotAfter:  time.Now().Add(2 * time.Hour),
		},
		nil,
		nil,
	)
	futureToken.Sign(privKey)
	assert.False(t, futureToken.IsValid(time.Now()))
}

func TestCapabilityToken_Allows(t *testing.T) {
	pubKey, privKey := generateKeyPair()
	deviceID := uuid.New().String()

	token := models.NewCapabilityToken(
		"test-issuer",
		uuid.New(),
		pubKey,
		[]models.Grant{
			{
				Resource: models.ResourceSelector{
					Type: "device",
					ID:   deviceID,
				},
				Actions: []models.ActionType{
					models.ActionConfigRead,
					models.ActionConfigWrite,
				},
			},
		},
		models.Validity{
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		},
		nil,
		nil,
	)
	token.Sign(privKey)

	// Allowed actions
	assert.True(t, token.Allows(models.ActionConfigRead, "device", deviceID))
	assert.True(t, token.Allows(models.ActionConfigWrite, "device", deviceID))

	// Not allowed actions
	assert.False(t, token.Allows(models.ActionExecCommand, "device", deviceID))
	assert.False(t, token.Allows(models.ActionConfigRead, "device", "other-device"))
	assert.False(t, token.Allows(models.ActionConfigRead, "network", deviceID))
}

// Config Block tests
func TestConfigBlock_SignAndVerify(t *testing.T) {
	pubKey, privKey := generateKeyPair()
	deviceID := uuid.New()
	authorID := uuid.New()

	config := &models.ConfigurationPayload{
		Format: models.ConfigFormatNormalized,
		Tree: &models.ConfigTree{
			System: &models.SystemConfig{
				Hostname: "router-01",
				Domain:   "example.com",
			},
		},
	}

	block := models.NewConfigBlock(
		deviceID,
		1,
		nil,
		&models.ConfigIntent{Description: "Initial config"},
		config,
		nil,
		nil,
		authorID,
	)

	// Sign
	block.Sign(privKey)
	assert.NotEmpty(t, block.AuthorSignature)
	assert.NotEmpty(t, block.BlockHash)

	// Verify
	isValid := block.Verify(pubKey)
	assert.True(t, isValid)

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	isValid = block.Verify(wrongPub)
	assert.False(t, isValid)
}

func TestConfigBlock_VerifyChain(t *testing.T) {
	_, privKey := generateKeyPair()
	deviceID := uuid.New()
	authorID := uuid.New()

	// First block
	block1 := models.NewConfigBlock(
		deviceID,
		1,
		nil,
		&models.ConfigIntent{Description: "Block 1"},
		&models.ConfigurationPayload{Format: models.ConfigFormatRaw, Raw: "config1"},
		nil,
		nil,
		authorID,
	)
	block1.Sign(privKey)

	// Second block
	block2 := models.NewConfigBlock(
		deviceID,
		2,
		block1.BlockHash,
		&models.ConfigIntent{Description: "Block 2"},
		&models.ConfigurationPayload{Format: models.ConfigFormatRaw, Raw: "config2"},
		nil,
		nil,
		authorID,
	)
	block2.Sign(privKey)

	// Verify chain
	assert.True(t, block1.VerifyChain(nil))
	assert.True(t, block2.VerifyChain(block1))

	// Invalid chain - wrong previous hash
	block3 := models.NewConfigBlock(
		deviceID,
		3,
		[]byte("wrong-hash"),
		&models.ConfigIntent{Description: "Block 3"},
		&models.ConfigurationPayload{Format: models.ConfigFormatRaw, Raw: "config3"},
		nil,
		nil,
		authorID,
	)
	assert.False(t, block3.VerifyChain(block2))
}

// Audit Event tests
func TestAuditEvent_ComputeAndVerifyHash(t *testing.T) {
	actorID := uuid.New()
	resourceID := uuid.New()

	event := models.NewAuditEventBuilder(models.AuditEventOperationExecute).
		WithSeverity(models.AuditSeverityInfo).
		WithActor(actorID, models.IdentityTypeOperator, "admin").
		WithResource("device", resourceID, "router-01").
		WithAction("config.write").
		WithResult(models.AuditResultSuccess).
		WithDuration(150).
		Build(1, nil)

	// Hash should be set
	assert.NotEmpty(t, event.EventHash)

	// Verify hash
	assert.True(t, event.Verify())

	// Tamper with event
	event.Action = "modified"
	assert.False(t, event.Verify())
}

func TestAuditEvent_VerifyChain(t *testing.T) {
	actorID := uuid.New()

	event1 := models.NewAuditEventBuilder(models.AuditEventIdentityAuth).
		WithActor(actorID, models.IdentityTypeOperator, "admin").
		WithResult(models.AuditResultSuccess).
		Build(1, nil)

	event2 := models.NewAuditEventBuilder(models.AuditEventOperationExecute).
		WithActor(actorID, models.IdentityTypeOperator, "admin").
		WithResult(models.AuditResultSuccess).
		Build(2, event1.EventHash)

	// Verify chain
	assert.True(t, event1.VerifyChain(nil))
	assert.True(t, event2.VerifyChain(event1))

	// Invalid chain
	event3 := models.NewAuditEventBuilder(models.AuditEventConfigDeploy).
		WithResult(models.AuditResultSuccess).
		Build(3, []byte("wrong-hash"))
	assert.False(t, event3.VerifyChain(event2))
}

// Signed Operation tests
func TestSignedOperation_SignAndVerify(t *testing.T) {
	pubKey, privKey := generateKeyPair()

	op, err := models.NewSignedOperation(
		"device-123",
		models.OperationTypeRead,
		"running-config",
		"show",
		map[string]interface{}{"format": "text"},
		[]byte("capability-token"),
		nil,
	)
	require.NoError(t, err)

	// Sign
	op.Sign(privKey)
	assert.NotEmpty(t, op.OperatorSignature)

	// Verify
	isValid := op.Verify(pubKey)
	assert.True(t, isValid)

	// Verify with wrong key
	wrongPub, _ := generateKeyPair()
	isValid = op.Verify(wrongPub)
	assert.False(t, isValid)
}

func TestSignedOperation_IsExpired(t *testing.T) {
	op, _ := models.NewSignedOperation(
		"device-123",
		models.OperationTypeRead,
		"config",
		"show",
		nil,
		nil,
		nil,
	)

	// Not expired
	assert.False(t, op.IsExpired(300000)) // 5 minutes

	// Set old timestamp
	op.Envelope.Timestamp = time.Now().Add(-10 * time.Minute).UnixMilli()
	assert.True(t, op.IsExpired(300000))
}

// Policy tests
func TestPolicy_Evaluate(t *testing.T) {
	// Test allow policy - only has allow rule
	allowPolicy := &models.Policy{
		ID:   uuid.New(),
		Name: "allow-policy",
		Definition: models.PolicyDefinition{
			Rules: []models.PolicyRule{
				{
					Name: "allow-network-admins",
					Subjects: models.SubjectMatcher{
						Groups: []string{"network-admins"},
					},
					Resources: models.ResourceMatcher{
						Types: []string{"device"},
					},
					Actions: []string{"config.read", "config.write"},
					Effect:  models.PolicyEffectAllow,
				},
			},
		},
	}

	// Test allowed request
	allowedReq := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:     uuid.New(),
			Groups: []string{"network-admins"},
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "router-01",
		},
		Action: "config.read",
		Context: models.PolicyContext{
			Time: time.Now(),
		},
	}

	decision := allowPolicy.Evaluate(allowedReq)
	assert.Equal(t, models.PolicyEffectAllow, decision.Decision)

	// Test default deny (no matching rule)
	noMatchReq := models.PolicyEvaluationRequest{
		Subject: models.PolicySubject{
			ID:     uuid.New(),
			Groups: []string{"viewers"},
		},
		Resource: models.PolicyResource{
			Type: "device",
			ID:   "router-01",
		},
		Action: "config.write",
		Context: models.PolicyContext{
			Time: time.Now(),
		},
	}

	decision = allowPolicy.Evaluate(noMatchReq)
	assert.Equal(t, models.PolicyEffectDeny, decision.Decision) // Default is deny

	// Test explicit deny policy
	denyPolicy := &models.Policy{
		ID:   uuid.New(),
		Name: "deny-policy",
		Definition: models.PolicyDefinition{
			Rules: []models.PolicyRule{
				{
					Name: "deny-all",
					Subjects: models.SubjectMatcher{
						Any: true,
					},
					Resources: models.ResourceMatcher{
						Any: true,
					},
					Actions: []string{"*"},
					Effect:  models.PolicyEffectDeny,
				},
			},
		},
	}

	decision = denyPolicy.Evaluate(allowedReq)
	assert.Equal(t, models.PolicyEffectDeny, decision.Decision)
}

// Device tests
func TestDevice_IsTrusted(t *testing.T) {
	device := models.NewDevice(
		"router-01",
		"Cisco",
		"ISR 4431",
		"SN123",
		"10.0.0.1",
		models.ProtocolTypeSSH,
	)

	assert.False(t, device.IsTrusted())

	device.UpdateTrustStatus(models.TrustStatusVerified)
	assert.True(t, device.IsTrusted())

	device.UpdateTrustStatus(models.TrustStatusUntrusted)
	assert.False(t, device.IsTrusted())
}

func TestDevice_IsCritical(t *testing.T) {
	device := models.NewDevice(
		"switch-01",
		"Cisco",
		"Nexus 9000",
		"SN456",
		"10.0.0.2",
		models.ProtocolTypeSSH,
	)

	device.Criticality = models.DeviceCriticalityLow
	assert.False(t, device.IsCritical())

	device.Criticality = models.DeviceCriticalityMedium
	assert.False(t, device.IsCritical())

	device.Criticality = models.DeviceCriticalityHigh
	assert.True(t, device.IsCritical())

	device.Criticality = models.DeviceCriticalityCritical
	assert.True(t, device.IsCritical())
}

// Benchmark tests
func BenchmarkCapabilityToken_Verify(b *testing.B) {
	pubKey, privKey := generateKeyPair()
	
	token := models.NewCapabilityToken(
		"test-issuer",
		uuid.New(),
		pubKey,
		[]models.Grant{},
		models.Validity{
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		},
		nil,
		nil,
	)
	token.Sign(privKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token.Verify(pubKey)
	}
}

func BenchmarkAuditEvent_ComputeHash(b *testing.B) {
	actorID := uuid.New()
	resourceID := uuid.New()

	builder := models.NewAuditEventBuilder(models.AuditEventOperationExecute).
		WithActor(actorID, models.IdentityTypeOperator, "admin").
		WithResource("device", resourceID, "router-01").
		WithAction("config.write").
		WithResult(models.AuditResultSuccess)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder.Build(int64(i), nil)
	}
}
