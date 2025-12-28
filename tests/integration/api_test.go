// +build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IntegrationTestSuite struct {
	suite.Suite
	apiURL     string
	httpClient *http.Client
	adminToken string
	adminKey   ed25519.PrivateKey
	adminPubKey ed25519.PublicKey
}

func TestIntegrationSuite(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration tests. Set INTEGRATION_TEST=true to run.")
	}
	suite.Run(t, new(IntegrationTestSuite))
}

func (s *IntegrationTestSuite) SetupSuite() {
	s.apiURL = os.Getenv("ZTNMS_API_URL")
	if s.apiURL == "" {
		s.apiURL = "https://localhost:8080"
	}

	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Generate admin keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(s.T(), err)
	s.adminKey = priv
	s.adminPubKey = pub
}

func (s *IntegrationTestSuite) TestHealthCheck() {
	resp, err := s.httpClient.Get(s.apiURL + "/health")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(s.T(), "healthy", result["status"])
}

func (s *IntegrationTestSuite) TestAuthentication() {
	// Step 1: Get challenge
	challengeResp, err := s.httpClient.Post(
		s.apiURL+"/api/v1/auth/challenge",
		"application/json",
		nil,
	)
	require.NoError(s.T(), err)
	defer challengeResp.Body.Close()

	var challengeResult struct {
		Challenge string `json:"challenge"`
		ExpiresAt string `json:"expires_at"`
	}
	json.NewDecoder(challengeResp.Body).Decode(&challengeResult)
	assert.NotEmpty(s.T(), challengeResult.Challenge)

	// Step 2: Sign challenge
	challenge, _ := base64.StdEncoding.DecodeString(challengeResult.Challenge)
	signature := ed25519.Sign(s.adminKey, challenge)

	// Step 3: Authenticate
	authReq := map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(s.adminPubKey),
		"challenge":  challengeResult.Challenge,
		"signature":  base64.StdEncoding.EncodeToString(signature),
	}
	authBody, _ := json.Marshal(authReq)

	authResp, err := s.httpClient.Post(
		s.apiURL+"/api/v1/auth/authenticate",
		"application/json",
		bytes.NewReader(authBody),
	)
	require.NoError(s.T(), err)
	defer authResp.Body.Close()

	// Should fail because identity doesn't exist yet
	assert.Equal(s.T(), http.StatusUnauthorized, authResp.StatusCode)
}

func (s *IntegrationTestSuite) TestIdentityLifecycle() {
	ctx := context.Background()

	// Create operator identity
	createReq := map[string]interface{}{
		"type": "operator",
		"attributes": map[string]interface{}{
			"username": fmt.Sprintf("testuser-%s", uuid.New().String()[:8]),
			"email":    "test@example.com",
			"groups":   []string{"network-admins"},
		},
		"public_key": base64.StdEncoding.EncodeToString(s.adminPubKey),
	}
	createBody, _ := json.Marshal(createReq)

	req, _ := http.NewRequestWithContext(ctx, "POST", s.apiURL+"/api/v1/identities", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken) // Would need valid token

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	// Check response (will depend on auth setup)
	body, _ := io.ReadAll(resp.Body)
	s.T().Logf("Create identity response: %d %s", resp.StatusCode, string(body))
}

func (s *IntegrationTestSuite) TestPolicyEvaluation() {
	ctx := context.Background()

	evalReq := map[string]interface{}{
		"subject": map[string]interface{}{
			"id":     uuid.New().String(),
			"type":   "operator",
			"groups": []string{"network-admins"},
		},
		"resource": map[string]interface{}{
			"type": "device",
			"id":   uuid.New().String(),
		},
		"action": "config.read",
		"context": map[string]interface{}{
			"time":         time.Now().Format(time.RFC3339),
			"mfa_verified": true,
		},
	}
	evalBody, _ := json.Marshal(evalReq)

	req, _ := http.NewRequestWithContext(ctx, "POST", s.apiURL+"/api/v1/policies/evaluate", bytes.NewReader(evalBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	s.T().Logf("Policy evaluation response: %d %s", resp.StatusCode, string(body))
}

func (s *IntegrationTestSuite) TestCapabilityTokenFlow() {
	ctx := context.Background()

	// Request capability
	capReq := map[string]interface{}{
		"grants": []map[string]interface{}{
			{
				"resource": map[string]string{
					"type": "device",
					"id":   uuid.New().String(),
				},
				"actions": []string{"config.read", "config.write"},
			},
		},
		"validity_duration": "8h",
	}
	capBody, _ := json.Marshal(capReq)

	req, _ := http.NewRequestWithContext(ctx, "POST", s.apiURL+"/api/v1/capabilities/request", bytes.NewReader(capBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	s.T().Logf("Capability request response: %d %s", resp.StatusCode, string(body))
}

func (s *IntegrationTestSuite) TestDeviceOperations() {
	ctx := context.Background()

	// List devices
	req, _ := http.NewRequestWithContext(ctx, "GET", s.apiURL+"/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	var result struct {
		Devices []interface{} `json:"devices"`
		Total   int           `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	s.T().Logf("Devices: %d", result.Total)
}

func (s *IntegrationTestSuite) TestConfigValidation() {
	ctx := context.Background()

	config := map[string]interface{}{
		"format": "normalized",
		"tree": map[string]interface{}{
			"system": map[string]string{
				"hostname": "test-router",
				"domain":   "example.com",
			},
			"interfaces": map[string]interface{}{
				"GigabitEthernet0/0": map[string]interface{}{
					"description": "WAN",
					"enabled":     true,
				},
			},
		},
	}

	validateReq := map[string]interface{}{
		"device_id":     uuid.New().String(),
		"configuration": config,
	}
	validateBody, _ := json.Marshal(validateReq)

	req, _ := http.NewRequestWithContext(ctx, "POST", s.apiURL+"/api/v1/configs/validate", bytes.NewReader(validateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	s.T().Logf("Config validation response: %d %s", resp.StatusCode, string(body))
}

func (s *IntegrationTestSuite) TestAuditEvents() {
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, "GET", s.apiURL+"/api/v1/audit/events?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+s.adminToken)

	resp, err := s.httpClient.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	var result struct {
		Events []interface{} `json:"events"`
		Total  int           `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	s.T().Logf("Audit events: %d", result.Total)
}

// Benchmark tests
func BenchmarkHealthCheck(b *testing.B) {
	apiURL := os.Getenv("ZTNMS_API_URL")
	if apiURL == "" {
		apiURL = "https://localhost:8080"
	}

	client := &http.Client{Timeout: 10 * time.Second}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(apiURL + "/health")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

func BenchmarkPolicyEvaluation(b *testing.B) {
	apiURL := os.Getenv("ZTNMS_API_URL")
	if apiURL == "" {
		apiURL = "https://localhost:8080"
	}

	client := &http.Client{Timeout: 10 * time.Second}

	evalReq := map[string]interface{}{
		"subject": map[string]interface{}{
			"id":     uuid.New().String(),
			"type":   "operator",
			"groups": []string{"network-admins"},
		},
		"resource": map[string]interface{}{
			"type": "device",
			"id":   uuid.New().String(),
		},
		"action": "config.read",
		"context": map[string]interface{}{
			"time": time.Now().Format(time.RFC3339),
		},
	}
	evalBody, _ := json.Marshal(evalReq)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", apiURL+"/api/v1/policies/evaluate", bytes.NewReader(evalBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}
