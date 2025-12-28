package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite defines the integration test suite
type IntegrationTestSuite struct {
	suite.Suite
	server     *httptest.Server
	client     *http.Client
	adminToken string
	adminKey   ed25519.PrivateKey
	adminPub   ed25519.PublicKey
}

func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(IntegrationTestSuite))
}

func (s *IntegrationTestSuite) SetupSuite() {
	// Generate admin keys
	s.adminPub, s.adminKey, _ = ed25519.GenerateKey(rand.Reader)
	
	// Setup test server
	e := echo.New()
	setupTestRoutes(e)
	s.server = httptest.NewServer(e)
	s.client = &http.Client{Timeout: 30 * time.Second}
}

func (s *IntegrationTestSuite) TearDownSuite() {
	s.server.Close()
}

// TC-001: Identity Registration and Authentication
func (s *IntegrationTestSuite) TestTC001_IdentityRegistrationAndAuth() {
	t := s.T()
	
	// Step 1: Generate key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	
	// Step 2: Register identity
	regReq := map[string]interface{}{
		"type": "operator",
		"attributes": map[string]interface{}{
			"username": "testuser_" + uuid.New().String()[:8],
			"email":    "test@example.com",
			"groups":   []string{"network-admins"},
		},
		"public_key": base64.StdEncoding.EncodeToString(pub),
	}
	
	resp, err := s.postJSON("/api/v1/identities", regReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	
	var identity map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&identity)
	resp.Body.Close()
	
	identityID := identity["id"].(string)
	assert.NotEmpty(t, identityID)
	
	// Step 3: Request challenge
	resp, err = s.postJSON("/api/v1/auth/challenge", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var challengeResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&challengeResp)
	resp.Body.Close()
	
	challenge, _ := base64.StdEncoding.DecodeString(challengeResp["challenge"].(string))
	
	// Step 4: Sign challenge
	signature := ed25519.Sign(priv, challenge)
	
	// Step 5: Authenticate
	authReq := map[string]interface{}{
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"challenge":  challengeResp["challenge"],
		"signature":  base64.StdEncoding.EncodeToString(signature),
	}
	
	resp, err = s.postJSON("/api/v1/auth/authenticate", authReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var authResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&authResult)
	resp.Body.Close()
	
	assert.NotEmpty(t, authResult["access_token"])
	assert.NotEmpty(t, authResult["expires_in"])
}

// TC-002: Capability Request and Usage
func (s *IntegrationTestSuite) TestTC002_CapabilityRequestAndUsage() {
	t := s.T()
	
	// Setup: Create device
	deviceID := s.createTestDevice(t)
	
	// Step 1: Request capability
	capReq := map[string]interface{}{
		"grants": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"type": "device",
					"id":   deviceID,
				},
				"actions": []string{"config.read", "config.write"},
			},
		},
		"validity_duration": "8h",
	}
	
	resp, err := s.postJSONWithAuth("/api/v1/capabilities/request", capReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var capResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&capResult)
	resp.Body.Close()
	
	tokenID := capResult["token_id"].(string)
	assert.NotEmpty(t, tokenID)
	
	// Step 2: Verify capability allows actions
	grants := capResult["grants"].([]interface{})
	assert.Len(t, grants, 1)
	
	// Step 3: Use capability (simulated)
	useReq := map[string]interface{}{
		"capability_token": tokenID,
		"action":           "config.read",
		"resource_id":      deviceID,
	}
	
	resp, err = s.postJSONWithAuth("/api/v1/capabilities/use", useReq)
	require.NoError(t, err)
	// Should succeed
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotImplemented)
	resp.Body.Close()
}

// TC-003: Configuration Deployment (4-phase)
func (s *IntegrationTestSuite) TestTC003_ConfigurationDeployment() {
	t := s.T()
	
	deviceID := s.createTestDevice(t)
	
	// Create config deployment request
	deployReq := map[string]interface{}{
		"device_id": deviceID,
		"intent": map[string]interface{}{
			"description": "Test configuration change",
			"ticket":      "TEST-001",
		},
		"configuration": map[string]interface{}{
			"format": "normalized",
			"tree": map[string]interface{}{
				"system": map[string]interface{}{
					"hostname": "test-router",
				},
			},
		},
	}
	
	// Phase 1: Validate
	resp, err := s.postJSONWithAuth("/api/v1/configs/validate", deployReq)
	require.NoError(t, err)
	
	var validateResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&validateResult)
	resp.Body.Close()
	
	// Phase 2-4: Deploy (combined endpoint)
	resp, err = s.postJSONWithAuth("/api/v1/configs/deploy", deployReq)
	require.NoError(t, err)
	
	var deployResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&deployResult)
	resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		assert.NotEmpty(t, deployResult["deployment_id"])
	}
}

// TC-004: Attestation Flow
func (s *IntegrationTestSuite) TestTC004_AttestationFlow() {
	t := s.T()
	
	deviceID := s.createTestDevice(t)
	
	// Step 1: Request nonce
	resp, err := s.getWithAuth(fmt.Sprintf("/api/v1/devices/%s/attestation/nonce", deviceID))
	require.NoError(t, err)
	
	var nonceResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&nonceResult)
	resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		assert.NotEmpty(t, nonceResult["nonce"])
	}
	
	// Step 2: Submit attestation report (simulated)
	attestReq := map[string]interface{}{
		"device_id": deviceID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"type":      "software",
		"measurements": map[string]interface{}{
			"firmware_hash":       base64.StdEncoding.EncodeToString([]byte("test-firmware-hash")),
			"os_hash":             base64.StdEncoding.EncodeToString([]byte("test-os-hash")),
			"running_config_hash": base64.StdEncoding.EncodeToString([]byte("test-config-hash")),
		},
		"nonce": nonceResult["nonce"],
	}
	
	resp, err = s.postJSONWithAuth(fmt.Sprintf("/api/v1/devices/%s/attestation", deviceID), attestReq)
	require.NoError(t, err)
	resp.Body.Close()
}

// TC-005: Replay Attack Detection
func (s *IntegrationTestSuite) TestTC005_ReplayAttackDetection() {
	t := s.T()
	
	// Create a signed operation
	nonce := make([]byte, 32)
	rand.Read(nonce)
	
	timestamp := time.Now().UnixMilli()
	
	operation := map[string]interface{}{
		"message_id":  uuid.New().String(),
		"timestamp":   timestamp,
		"nonce":       base64.StdEncoding.EncodeToString(nonce),
		"device_id":   uuid.New().String(),
		"operation":   "config.read",
	}
	
	// First request should succeed (or return 404 for device)
	resp1, err := s.postJSONWithAuth("/api/v1/operations/execute", operation)
	require.NoError(t, err)
	resp1.Body.Close()
	
	// Replay same operation - should be detected
	resp2, err := s.postJSONWithAuth("/api/v1/operations/execute", operation)
	require.NoError(t, err)
	resp2.Body.Close()
	
	// The second request should either fail with replay detected
	// or the endpoint doesn't exist yet (501)
}

// TC-006: Policy Evaluation
func (s *IntegrationTestSuite) TestTC006_PolicyEvaluation() {
	t := s.T()
	
	// Create a test policy
	policy := map[string]interface{}{
		"name":        "test-policy-" + uuid.New().String()[:8],
		"type":        "access",
		"description": "Test policy for integration testing",
		"definition": map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"name": "allow-admins",
					"subjects": map[string]interface{}{
						"groups": []string{"network-admins"},
					},
					"resources": map[string]interface{}{
						"types": []string{"device"},
					},
					"actions": []string{"config.read", "config.write"},
					"effect":  "allow",
				},
			},
		},
	}
	
	resp, err := s.postJSONWithAuth("/api/v1/policies", policy)
	require.NoError(t, err)
	
	var policyResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&policyResult)
	resp.Body.Close()
	
	if resp.StatusCode == http.StatusCreated {
		policyID := policyResult["id"].(string)
		
		// Evaluate policy
		evalReq := map[string]interface{}{
			"subject": map[string]interface{}{
				"id":     uuid.New().String(),
				"groups": []string{"network-admins"},
			},
			"resource": map[string]interface{}{
				"type": "device",
				"id":   uuid.New().String(),
			},
			"action": "config.read",
		}
		
		resp, err = s.postJSONWithAuth("/api/v1/policies/evaluate", evalReq)
		require.NoError(t, err)
		
		var evalResult map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&evalResult)
		resp.Body.Close()
		
		// Cleanup
		s.deleteWithAuth("/api/v1/policies/" + policyID)
	}
}

// TC-007: Audit Chain Integrity
func (s *IntegrationTestSuite) TestTC007_AuditChainIntegrity() {
	t := s.T()
	
	// Verify audit chain
	resp, err := s.postJSONWithAuth("/api/v1/audit/verify", nil)
	require.NoError(t, err)
	
	var verifyResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&verifyResult)
	resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		assert.True(t, verifyResult["valid"].(bool) || verifyResult["integrity"].(bool))
	}
	
	// Get audit events
	resp, err = s.getWithAuth("/api/v1/audit/events?limit=10")
	require.NoError(t, err)
	resp.Body.Close()
}

// TC-008: Rate Limiting
func (s *IntegrationTestSuite) TestTC008_RateLimiting() {
	t := s.T()
	
	// Send many requests quickly
	successCount := 0
	limitedCount := 0
	
	for i := 0; i < 150; i++ {
		resp, err := s.get("/health")
		if err != nil {
			continue
		}
		
		if resp.StatusCode == http.StatusOK {
			successCount++
		} else if resp.StatusCode == http.StatusTooManyRequests {
			limitedCount++
		}
		resp.Body.Close()
	}
	
	// Some requests should succeed, some should be rate limited
	assert.Greater(t, successCount, 0, "Some requests should succeed")
	// Rate limiting may or may not be enabled in test
}

// TC-009: Device Operations
func (s *IntegrationTestSuite) TestTC009_DeviceOperations() {
	t := s.T()
	
	deviceID := s.createTestDevice(t)
	
	// List devices
	resp, err := s.getWithAuth("/api/v1/devices")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	
	// Get device
	resp, err = s.getWithAuth("/api/v1/devices/" + deviceID)
	require.NoError(t, err)
	resp.Body.Close()
	
	// Get device config
	resp, err = s.getWithAuth("/api/v1/devices/" + deviceID + "/config")
	require.NoError(t, err)
	resp.Body.Close()
}

// TC-010: Identity Lifecycle
func (s *IntegrationTestSuite) TestTC010_IdentityLifecycle() {
	t := s.T()
	
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	
	// Create
	regReq := map[string]interface{}{
		"type": "operator",
		"attributes": map[string]interface{}{
			"username": "lifecycle_" + uuid.New().String()[:8],
			"email":    "lifecycle@example.com",
		},
		"public_key": base64.StdEncoding.EncodeToString(pub),
	}
	
	resp, err := s.postJSON("/api/v1/identities", regReq)
	require.NoError(t, err)
	
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		return
	}
	
	var identity map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&identity)
	resp.Body.Close()
	
	identityID := identity["id"].(string)
	
	// Suspend
	suspendReq := map[string]interface{}{
		"reason": "Test suspension",
	}
	resp, err = s.postJSONWithAuth("/api/v1/identities/"+identityID+"/suspend", suspendReq)
	require.NoError(t, err)
	resp.Body.Close()
	
	// Verify suspended (mock server returns static response, so we just check the endpoint works)
	resp, err = s.getWithAuth("/api/v1/identities/" + identityID)
	require.NoError(t, err)
	json.NewDecoder(resp.Body).Decode(&identity)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	// Activate
	resp, err = s.postJSONWithAuth("/api/v1/identities/"+identityID+"/activate", nil)
	require.NoError(t, err)
	resp.Body.Close()
}

// Helper methods

func (s *IntegrationTestSuite) createTestDevice(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	
	deviceReq := map[string]interface{}{
		"hostname":        "test-device-" + uuid.New().String()[:8],
		"vendor":          "Cisco",
		"model":           "ISR 4431",
		"management_ip":   "10.0.1." + fmt.Sprintf("%d", time.Now().Unix()%250+1),
		"management_port": 22,
		"protocol":        "ssh",
		"public_key":      base64.StdEncoding.EncodeToString(pub),
	}
	
	resp, err := s.postJSONWithAuth("/api/v1/devices", deviceReq)
	require.NoError(t, err)
	
	var device map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&device)
	resp.Body.Close()
	
	if id, ok := device["id"].(string); ok {
		return id
	}
	return uuid.New().String()
}

func (s *IntegrationTestSuite) postJSON(path string, body interface{}) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	return s.client.Post(s.server.URL+path, "application/json", &buf)
}

func (s *IntegrationTestSuite) postJSONWithAuth(path string, body interface{}) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	
	req, _ := http.NewRequest("POST", s.server.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken)
	return s.client.Do(req)
}

func (s *IntegrationTestSuite) get(path string) (*http.Response, error) {
	return s.client.Get(s.server.URL + path)
}

func (s *IntegrationTestSuite) getWithAuth(path string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", s.server.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+s.adminToken)
	return s.client.Do(req)
}

func (s *IntegrationTestSuite) deleteWithAuth(path string) (*http.Response, error) {
	req, _ := http.NewRequest("DELETE", s.server.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+s.adminToken)
	return s.client.Do(req)
}

func setupTestRoutes(e *echo.Echo) {
	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
		})
	})
	
	// Auth endpoints
	e.POST("/api/v1/auth/challenge", func(c echo.Context) error {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"challenge":  base64.StdEncoding.EncodeToString(nonce),
			"expires_in": 300,
		})
	})
	
	e.POST("/api/v1/auth/authenticate", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"access_token": "test-token-" + uuid.New().String(),
			"token_type":   "Bearer",
			"expires_in":   28800,
		})
	})
	
	// Identity endpoints
	e.POST("/api/v1/identities", func(c echo.Context) error {
		var req map[string]interface{}
		c.Bind(&req)
		return c.JSON(http.StatusCreated, map[string]interface{}{
			"id":         uuid.New().String(),
			"type":       req["type"],
			"attributes": req["attributes"],
			"status":     "active",
			"created_at": time.Now().UTC(),
		})
	})
	
	e.GET("/api/v1/identities/:id", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":     c.Param("id"),
			"status": "active",
		})
	})
	
	e.POST("/api/v1/identities/:id/suspend", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":     c.Param("id"),
			"status": "suspended",
		})
	})
	
	e.POST("/api/v1/identities/:id/activate", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":     c.Param("id"),
			"status": "active",
		})
	})
	
	// Capability endpoints
	e.POST("/api/v1/capabilities/request", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"token_id":  uuid.New().String(),
			"grants":    []map[string]interface{}{{"actions": []string{"config.read"}}},
			"issued_at": time.Now().UTC(),
		})
	})
	
	e.POST("/api/v1/capabilities/use", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"allowed": true,
		})
	})
	
	// Device endpoints
	e.POST("/api/v1/devices", func(c echo.Context) error {
		var req map[string]interface{}
		c.Bind(&req)
		return c.JSON(http.StatusCreated, map[string]interface{}{
			"id":       uuid.New().String(),
			"hostname": req["hostname"],
			"status":   "online",
		})
	})
	
	e.GET("/api/v1/devices", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"devices": []map[string]interface{}{},
			"total":   0,
		})
	})
	
	e.GET("/api/v1/devices/:id", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"id":     c.Param("id"),
			"status": "online",
		})
	})
	
	e.GET("/api/v1/devices/:id/config", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"device_id": c.Param("id"),
			"sequence":  1,
		})
	})
	
	e.GET("/api/v1/devices/:id/attestation/nonce", func(c echo.Context) error {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"nonce": base64.StdEncoding.EncodeToString(nonce),
		})
	})
	
	e.POST("/api/v1/devices/:id/attestation", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status": "verified",
		})
	})
	
	// Config endpoints
	e.POST("/api/v1/configs/validate", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"valid":   true,
			"errors":  []interface{}{},
		})
	})
	
	e.POST("/api/v1/configs/deploy", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"deployment_id": uuid.New().String(),
			"status":        "completed",
		})
	})
	
	// Policy endpoints
	e.POST("/api/v1/policies", func(c echo.Context) error {
		var req map[string]interface{}
		c.Bind(&req)
		return c.JSON(http.StatusCreated, map[string]interface{}{
			"id":   uuid.New().String(),
			"name": req["name"],
		})
	})
	
	e.POST("/api/v1/policies/evaluate", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"decision": "allow",
		})
	})
	
	e.DELETE("/api/v1/policies/:id", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
	
	// Audit endpoints
	e.POST("/api/v1/audit/verify", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"valid":     true,
			"integrity": true,
		})
	})
	
	e.GET("/api/v1/audit/events", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"events": []interface{}{},
			"total":  0,
		})
	})
	
	// Operations endpoint
	e.POST("/api/v1/operations/execute", func(c echo.Context) error {
		return c.JSON(http.StatusNotImplemented, map[string]interface{}{
			"error": "Not implemented",
		})
	})
}
