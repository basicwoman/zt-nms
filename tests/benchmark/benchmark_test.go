package benchmark_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestBenchmarkHelpers verifies benchmark helper functions work correctly
func TestBenchmarkHelpers(t *testing.T) {
	t.Run("createTestPolicy", func(t *testing.T) {
		policy := createTestPolicy()
		assert.NotEmpty(t, policy["id"])
		assert.Equal(t, "test-policy", policy["name"])
	})

	t.Run("createTestRequest", func(t *testing.T) {
		request := createTestRequest()
		assert.NotNil(t, request["subject"])
		assert.NotNil(t, request["resource"])
		assert.Equal(t, "config.read", request["action"])
	})

	t.Run("evaluatePolicy", func(t *testing.T) {
		policy := createTestPolicy()
		request := createTestRequest()
		result := evaluatePolicy(policy, request)
		assert.Equal(t, "allow", result)
	})

	t.Run("createCapabilityToken", func(t *testing.T) {
		token := createCapabilityToken()
		assert.NotEmpty(t, token["token_id"])
		assert.Equal(t, 1, token["version"])
	})

	t.Run("signAndVerifyToken", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		token := createCapabilityToken()
		signToken(token, priv)
		assert.True(t, verifyToken(token, pub))
	})

	t.Run("createAuditEvent", func(t *testing.T) {
		event := createAuditEvent(1)
		assert.NotEmpty(t, event["id"])
		assert.Equal(t, int64(1), event["sequence"])
	})

	t.Run("verifyChain", func(t *testing.T) {
		events := make([]map[string]interface{}, 3)
		var prevHash []byte
		for i := range events {
			events[i] = createAuditEvent(int64(i))
			events[i]["prev_hash"] = prevHash
			prevHash = computeHash(events[i])
			events[i]["event_hash"] = prevHash
		}
		assert.True(t, verifyChain(events))
	})
}

// BenchmarkEd25519Sign benchmarks Ed25519 signature generation
func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := make([]byte, 256)
	rand.Read(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, message)
	}
}

// BenchmarkEd25519Verify benchmarks Ed25519 signature verification
func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := make([]byte, 256)
	rand.Read(message)
	signature := ed25519.Sign(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, message, signature)
	}
}

// BenchmarkUUIDGeneration benchmarks UUID generation
func BenchmarkUUIDGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uuid.New()
	}
}

// BenchmarkJSONMarshal benchmarks JSON marshaling of capability token
func BenchmarkJSONMarshal(b *testing.B) {
	token := map[string]interface{}{
		"token_id":   uuid.New().String(),
		"version":    1,
		"issuer":     "test-issuer",
		"subject_id": uuid.New().String(),
		"grants": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"type": "device",
					"id":   uuid.New().String(),
				},
				"actions": []string{"config.read", "config.write"},
			},
		},
		"validity": map[string]interface{}{
			"not_before": time.Now().Unix(),
			"not_after":  time.Now().Add(8 * time.Hour).Unix(),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(token)
	}
}

// BenchmarkJSONUnmarshal benchmarks JSON unmarshaling
func BenchmarkJSONUnmarshal(b *testing.B) {
	token := map[string]interface{}{
		"token_id":   uuid.New().String(),
		"version":    1,
		"issuer":     "test-issuer",
		"subject_id": uuid.New().String(),
		"grants": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"type": "device",
					"id":   uuid.New().String(),
				},
				"actions": []string{"config.read", "config.write"},
			},
		},
	}
	data, _ := json.Marshal(token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result map[string]interface{}
		json.Unmarshal(data, &result)
	}
}

// BenchmarkPolicyEvaluationSimple benchmarks simple policy evaluation
func BenchmarkPolicyEvaluationSimple(b *testing.B) {
	policy := createTestPolicy()
	request := createTestRequest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluatePolicy(policy, request)
	}
}

// BenchmarkPolicyEvaluationComplex benchmarks complex policy evaluation
func BenchmarkPolicyEvaluationComplex(b *testing.B) {
	policies := make([]map[string]interface{}, 10)
	for i := range policies {
		policies[i] = createTestPolicy()
	}
	request := createTestRequest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, policy := range policies {
			evaluatePolicy(policy, request)
		}
	}
}

// BenchmarkCapabilityTokenCreation benchmarks capability token creation
func BenchmarkCapabilityTokenCreation(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token := createCapabilityToken()
		signToken(token, priv)
	}
}

// BenchmarkCapabilityTokenVerification benchmarks capability token verification
func BenchmarkCapabilityTokenVerification(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := createCapabilityToken()
	signToken(token, priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyToken(token, pub)
	}
}

// BenchmarkAuditEventCreation benchmarks audit event creation
func BenchmarkAuditEventCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		createAuditEvent(int64(i))
	}
}

// BenchmarkHashChainVerification benchmarks hash chain verification
func BenchmarkHashChainVerification(b *testing.B) {
	events := make([]map[string]interface{}, 100)
	var prevHash []byte
	for i := range events {
		events[i] = createAuditEvent(int64(i))
		events[i]["prev_hash"] = prevHash
		prevHash = computeHash(events[i])
		events[i]["event_hash"] = prevHash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyChain(events)
	}
}

// BenchmarkConcurrentPolicyEvaluation benchmarks concurrent policy evaluation
func BenchmarkConcurrentPolicyEvaluation(b *testing.B) {
	policy := createTestPolicy()
	request := createTestRequest()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			evaluatePolicy(policy, request)
		}
	})
}

// Helper functions

func createTestPolicy() map[string]interface{} {
	return map[string]interface{}{
		"id":   uuid.New().String(),
		"name": "test-policy",
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
	}
}

func createTestRequest() map[string]interface{} {
	return map[string]interface{}{
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
}

func evaluatePolicy(policy, request map[string]interface{}) string {
	rules := policy["rules"].([]map[string]interface{})
	reqSubject := request["subject"].(map[string]interface{})
	reqResource := request["resource"].(map[string]interface{})
	reqAction := request["action"].(string)

	for _, rule := range rules {
		subjects := rule["subjects"].(map[string]interface{})
		resources := rule["resources"].(map[string]interface{})
		actions := rule["actions"].([]string)

		// Check subject groups
		if groups, ok := subjects["groups"].([]string); ok {
			reqGroups := reqSubject["groups"].([]string)
			if !hasOverlap(groups, reqGroups) {
				continue
			}
		}

		// Check resource type
		if types, ok := resources["types"].([]string); ok {
			reqType := reqResource["type"].(string)
			if !contains(types, reqType) {
				continue
			}
		}

		// Check action
		if !contains(actions, reqAction) {
			continue
		}

		return rule["effect"].(string)
	}

	return "deny"
}

func createCapabilityToken() map[string]interface{} {
	return map[string]interface{}{
		"token_id":   uuid.New().String(),
		"version":    1,
		"issuer":     "test-issuer",
		"subject_id": uuid.New().String(),
		"issued_at":  time.Now().Unix(),
		"grants": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"type": "device",
					"id":   uuid.New().String(),
				},
				"actions": []string{"config.read"},
			},
		},
		"validity": map[string]interface{}{
			"not_before": time.Now().Unix(),
			"not_after":  time.Now().Add(8 * time.Hour).Unix(),
		},
	}
}

func signToken(token map[string]interface{}, key ed25519.PrivateKey) {
	data, _ := json.Marshal(token)
	token["signature"] = ed25519.Sign(key, data)
}

func verifyToken(token map[string]interface{}, key ed25519.PublicKey) bool {
	sig := token["signature"].([]byte)
	delete(token, "signature")
	data, _ := json.Marshal(token)
	token["signature"] = sig
	return ed25519.Verify(key, data, sig)
}

func createAuditEvent(sequence int64) map[string]interface{} {
	return map[string]interface{}{
		"id":         uuid.New().String(),
		"sequence":   sequence,
		"timestamp":  time.Now().Unix(),
		"event_type": "operation.execute",
		"actor_id":   uuid.New().String(),
		"action":     "config.read",
		"result":     "success",
	}
}

func computeHash(event map[string]interface{}) []byte {
	data, _ := json.Marshal(event)
	hash := make([]byte, 32)
	copy(hash, data[:32])
	return hash
}

func verifyChain(events []map[string]interface{}) bool {
	for i := 1; i < len(events); i++ {
		prevHash := events[i]["prev_hash"].([]byte)
		expectedHash := events[i-1]["event_hash"].([]byte)
		if string(prevHash) != string(expectedHash) {
			return false
		}
	}
	return true
}

func hasOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
