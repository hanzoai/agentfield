package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPropagateKeyContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret-key-32bytes!!!!!!")

	t.Run("adds all required headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(ContextKeyID, "key-123")
		c.Set(ContextKeyName, "test-key")
		c.Set(ContextKeyScopes, []string{"finance", "hr"})

		outReq, _ := http.NewRequest(http.MethodGet, "http://agent/execute", nil)
		PropagateKeyContext(c, outReq, secret)

		assert.Equal(t, "key-123", outReq.Header.Get(HeaderAPIKeyID))
		assert.Equal(t, "test-key", outReq.Header.Get(HeaderAPIKeyName))

		// Verify scopes JSON
		var scopes []string
		err := json.Unmarshal([]byte(outReq.Header.Get(HeaderAPIKeyScopes)), &scopes)
		require.NoError(t, err)
		assert.Equal(t, []string{"finance", "hr"}, scopes)

		// Verify timestamp is set
		ts := outReq.Header.Get(HeaderAPIKeyTimestamp)
		assert.NotEmpty(t, ts)
		_, err = time.Parse(time.RFC3339, ts)
		require.NoError(t, err)

		// Verify signature is set
		sig := outReq.Header.Get(HeaderAPIKeySignature)
		assert.NotEmpty(t, sig)
		assert.Len(t, sig, 64) // HMAC-SHA256 hex encoded
	})

	t.Run("skips if no key ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		// No key ID set

		outReq, _ := http.NewRequest(http.MethodGet, "http://agent/execute", nil)
		PropagateKeyContext(c, outReq, secret)

		assert.Empty(t, outReq.Header.Get(HeaderAPIKeyID))
		assert.Empty(t, outReq.Header.Get(HeaderAPIKeySignature))
	})

	t.Run("handles empty scopes", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(ContextKeyID, "key-123")
		c.Set(ContextKeyName, "super-key")
		c.Set(ContextKeyScopes, []string{})

		outReq, _ := http.NewRequest(http.MethodGet, "http://agent/execute", nil)
		PropagateKeyContext(c, outReq, secret)

		var scopes []string
		err := json.Unmarshal([]byte(outReq.Header.Get(HeaderAPIKeyScopes)), &scopes)
		require.NoError(t, err)
		assert.Empty(t, scopes)
	})
}

func TestPropagateKeyContextFromValues(t *testing.T) {
	secret := []byte("test-secret-key-32bytes!!!!!!")

	t.Run("propagates with explicit values", func(t *testing.T) {
		outReq, _ := http.NewRequest(http.MethodGet, "http://agent/execute", nil)
		PropagateKeyContextFromValues(outReq, "key-abc", "explicit-key", []string{"admin"}, secret)

		assert.Equal(t, "key-abc", outReq.Header.Get(HeaderAPIKeyID))
		assert.Equal(t, "explicit-key", outReq.Header.Get(HeaderAPIKeyName))
		assert.NotEmpty(t, outReq.Header.Get(HeaderAPIKeySignature))
	})

	t.Run("skips if empty key ID", func(t *testing.T) {
		outReq, _ := http.NewRequest(http.MethodGet, "http://agent/execute", nil)
		PropagateKeyContextFromValues(outReq, "", "name", []string{"scope"}, secret)

		assert.Empty(t, outReq.Header.Get(HeaderAPIKeyID))
	})
}

func TestVerifyAndExtractPropagatedKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := []byte("test-secret-key-32bytes!!!!!!")

	t.Run("valid propagation", func(t *testing.T) {
		// Create signed headers
		timestamp := time.Now().UTC().Format(time.RFC3339)
		scopes := []string{"finance", "hr"}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-123", "test-key", scopes, timestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		keyID, keyName, extractedScopes, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.NoError(t, err)
		assert.Equal(t, "key-123", keyID)
		assert.Equal(t, "test-key", keyName)
		assert.Equal(t, []string{"finance", "hr"}, extractedScopes)
	})

	t.Run("no propagation headers returns empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)

		keyID, keyName, scopes, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.NoError(t, err)
		assert.Empty(t, keyID)
		assert.Empty(t, keyName)
		assert.Nil(t, scopes)
	})

	t.Run("incomplete headers returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		// Missing timestamp and signature

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete propagation headers")
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyTimestamp, "not-a-timestamp")
		c.Request.Header.Set(HeaderAPIKeySignature, "sig")

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid propagation timestamp")
	})

	t.Run("expired timestamp rejected", func(t *testing.T) {
		// Timestamp from 10 minutes ago
		oldTimestamp := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
		scopes := []string{}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-123", "test-key", scopes, oldTimestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, oldTimestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "propagation headers expired")
	})

	t.Run("future timestamp rejected", func(t *testing.T) {
		// Timestamp 5 minutes in the future (beyond 1 minute tolerance)
		futureTimestamp := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
		scopes := []string{}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-123", "test-key", scopes, futureTimestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, futureTimestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "propagation timestamp in future")
	})

	t.Run("invalid signature rejected", func(t *testing.T) {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		scopes := []string{"finance"}
		scopesJSON, _ := json.Marshal(scopes)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, "invalid-signature")

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid propagation signature")
	})

	t.Run("tampered key ID detected", func(t *testing.T) {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		scopes := []string{"finance"}
		scopesJSON, _ := json.Marshal(scopes)
		// Sign with original key ID
		signature := signKeyContext("key-123", "test-key", scopes, timestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		// But send tampered key ID
		c.Request.Header.Set(HeaderAPIKeyID, "key-TAMPERED")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid propagation signature")
	})

	t.Run("tampered scopes detected", func(t *testing.T) {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		originalScopes := []string{"read-only"}
		// Sign with original scopes
		signature := signKeyContext("key-123", "test-key", originalScopes, timestamp, secret)

		// But send escalated scopes
		tamperedScopes := []string{"admin", "super"}
		tamperedJSON, _ := json.Marshal(tamperedScopes)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(tamperedJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid propagation signature")
	})

	t.Run("invalid scopes JSON", func(t *testing.T) {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		signature := signKeyContext("key-123", "test-key", nil, timestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, "not-valid-json")
		c.Request.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scopes format")
	})

	t.Run("clock skew within tolerance accepted", func(t *testing.T) {
		// Timestamp 30 seconds in the future (within 1 minute tolerance)
		futureTimestamp := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339)
		scopes := []string{"finance"}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-123", "test-key", scopes, futureTimestamp, secret)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set(HeaderAPIKeyID, "key-123")
		c.Request.Header.Set(HeaderAPIKeyName, "test-key")
		c.Request.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		c.Request.Header.Set(HeaderAPIKeyTimestamp, futureTimestamp)
		c.Request.Header.Set(HeaderAPIKeySignature, signature)

		keyID, _, _, err := VerifyAndExtractPropagatedKey(c, secret, DefaultPropagationMaxAge)

		require.NoError(t, err)
		assert.Equal(t, "key-123", keyID)
	})
}

func TestVerifyAndExtractPropagatedKeyFromRequest(t *testing.T) {
	secret := []byte("test-secret-key-32bytes!!!!!!")

	t.Run("valid propagation via http.Request", func(t *testing.T) {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		scopes := []string{"finance"}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-http", "http-key", scopes, timestamp, secret)

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(HeaderAPIKeyID, "key-http")
		req.Header.Set(HeaderAPIKeyName, "http-key")
		req.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		req.Header.Set(HeaderAPIKeyTimestamp, timestamp)
		req.Header.Set(HeaderAPIKeySignature, signature)

		keyID, keyName, extractedScopes, err := VerifyAndExtractPropagatedKeyFromRequest(req, secret, DefaultPropagationMaxAge)

		require.NoError(t, err)
		assert.Equal(t, "key-http", keyID)
		assert.Equal(t, "http-key", keyName)
		assert.Equal(t, []string{"finance"}, extractedScopes)
	})

	t.Run("expired headers rejected", func(t *testing.T) {
		oldTimestamp := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
		scopes := []string{}
		scopesJSON, _ := json.Marshal(scopes)
		signature := signKeyContext("key-123", "test", scopes, oldTimestamp, secret)

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(HeaderAPIKeyID, "key-123")
		req.Header.Set(HeaderAPIKeyName, "test")
		req.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
		req.Header.Set(HeaderAPIKeyTimestamp, oldTimestamp)
		req.Header.Set(HeaderAPIKeySignature, signature)

		_, _, _, err := VerifyAndExtractPropagatedKeyFromRequest(req, secret, DefaultPropagationMaxAge)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "propagation headers expired")
	})
}

func TestSignKeyContext(t *testing.T) {
	secret := []byte("test-secret")

	t.Run("deterministic signature", func(t *testing.T) {
		sig1 := signKeyContext("id", "name", []string{"a", "b"}, "2024-01-01T00:00:00Z", secret)
		sig2 := signKeyContext("id", "name", []string{"a", "b"}, "2024-01-01T00:00:00Z", secret)

		assert.Equal(t, sig1, sig2)
	})

	t.Run("different inputs produce different signatures", func(t *testing.T) {
		sig1 := signKeyContext("id1", "name", []string{}, "2024-01-01T00:00:00Z", secret)
		sig2 := signKeyContext("id2", "name", []string{}, "2024-01-01T00:00:00Z", secret)

		assert.NotEqual(t, sig1, sig2)
	})

	t.Run("scope order matters", func(t *testing.T) {
		sig1 := signKeyContext("id", "name", []string{"a", "b"}, "2024-01-01T00:00:00Z", secret)
		sig2 := signKeyContext("id", "name", []string{"b", "a"}, "2024-01-01T00:00:00Z", secret)

		assert.NotEqual(t, sig1, sig2)
	})

	t.Run("different secrets produce different signatures", func(t *testing.T) {
		sig1 := signKeyContext("id", "name", []string{}, "2024-01-01T00:00:00Z", []byte("secret1"))
		sig2 := signKeyContext("id", "name", []string{}, "2024-01-01T00:00:00Z", []byte("secret2"))

		assert.NotEqual(t, sig1, sig2)
	})
}

func TestKeyPropagationHeaders(t *testing.T) {
	headers := KeyPropagationHeaders()

	assert.Contains(t, headers, HeaderAPIKeyID)
	assert.Contains(t, headers, HeaderAPIKeyName)
	assert.Contains(t, headers, HeaderAPIKeyScopes)
	assert.Contains(t, headers, HeaderAPIKeySignature)
	assert.Contains(t, headers, HeaderAPIKeyTimestamp)
	assert.Len(t, headers, 5)
}

func TestCopyPropagationHeaders(t *testing.T) {
	src, _ := http.NewRequest(http.MethodGet, "/", nil)
	src.Header.Set(HeaderAPIKeyID, "key-123")
	src.Header.Set(HeaderAPIKeyName, "test-key")
	src.Header.Set(HeaderAPIKeyScopes, `["finance"]`)
	src.Header.Set(HeaderAPIKeyTimestamp, "2024-01-01T00:00:00Z")
	src.Header.Set(HeaderAPIKeySignature, "abc123")
	src.Header.Set("X-Other-Header", "should-not-copy")

	dst, _ := http.NewRequest(http.MethodPost, "/other", nil)
	CopyPropagationHeaders(src, dst)

	assert.Equal(t, "key-123", dst.Header.Get(HeaderAPIKeyID))
	assert.Equal(t, "test-key", dst.Header.Get(HeaderAPIKeyName))
	assert.Equal(t, `["finance"]`, dst.Header.Get(HeaderAPIKeyScopes))
	assert.Equal(t, "2024-01-01T00:00:00Z", dst.Header.Get(HeaderAPIKeyTimestamp))
	assert.Equal(t, "abc123", dst.Header.Get(HeaderAPIKeySignature))
	assert.Empty(t, dst.Header.Get("X-Other-Header"))
}

func TestCopyPropagationHeaders_Partial(t *testing.T) {
	src, _ := http.NewRequest(http.MethodGet, "/", nil)
	src.Header.Set(HeaderAPIKeyID, "key-only")
	// Missing other headers

	dst, _ := http.NewRequest(http.MethodPost, "/other", nil)
	CopyPropagationHeaders(src, dst)

	assert.Equal(t, "key-only", dst.Header.Get(HeaderAPIKeyID))
	assert.Empty(t, dst.Header.Get(HeaderAPIKeyName))
}

func TestPropagationRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := []byte("shared-secret-for-agents!!!!!!!")

	// Simulate control plane setting context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(ContextKeyID, "round-trip-key")
	c.Set(ContextKeyName, "integration-key")
	c.Set(ContextKeyScopes, []string{"workflow-1", "workflow-2"})

	// Control plane propagates to agent request
	agentReq, _ := http.NewRequest(http.MethodPost, "http://agent:8080/execute", nil)
	PropagateKeyContext(c, agentReq, secret)

	// Agent receives and verifies
	agentC, _ := gin.CreateTestContext(httptest.NewRecorder())
	agentC.Request = agentReq

	keyID, keyName, scopes, err := VerifyAndExtractPropagatedKey(agentC, secret, DefaultPropagationMaxAge)

	require.NoError(t, err)
	assert.Equal(t, "round-trip-key", keyID)
	assert.Equal(t, "integration-key", keyName)
	assert.Equal(t, []string{"workflow-1", "workflow-2"}, scopes)
}

func TestPropagationRoundTrip_ChainedAgents(t *testing.T) {
	secret := []byte("shared-secret-for-agents!!!!!!!")

	// Original request from control plane
	originalReq, _ := http.NewRequest(http.MethodPost, "http://agent1:8080/execute", nil)
	PropagateKeyContextFromValues(originalReq, "chain-key", "chained", []string{"finance"}, secret)

	// Agent 1 forwards to Agent 2 using CopyPropagationHeaders
	agent2Req, _ := http.NewRequest(http.MethodPost, "http://agent2:8080/execute", nil)
	CopyPropagationHeaders(originalReq, agent2Req)

	// Agent 2 can verify the forwarded headers
	keyID, keyName, scopes, err := VerifyAndExtractPropagatedKeyFromRequest(agent2Req, secret, DefaultPropagationMaxAge)

	require.NoError(t, err)
	assert.Equal(t, "chain-key", keyID)
	assert.Equal(t, "chained", keyName)
	assert.Equal(t, []string{"finance"}, scopes)
}

func TestReplayAttackPrevention(t *testing.T) {
	secret := []byte("test-secret-key-32bytes!!!!!!")

	// Create valid signed headers
	timestamp := time.Now().UTC().Format(time.RFC3339)
	scopes := []string{"finance"}
	scopesJSON, _ := json.Marshal(scopes)
	signature := signKeyContext("key-123", "test-key", scopes, timestamp, secret)

	// First request should succeed
	req1, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set(HeaderAPIKeyID, "key-123")
	req1.Header.Set(HeaderAPIKeyName, "test-key")
	req1.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
	req1.Header.Set(HeaderAPIKeyTimestamp, timestamp)
	req1.Header.Set(HeaderAPIKeySignature, signature)

	keyID, _, _, err := VerifyAndExtractPropagatedKeyFromRequest(req1, secret, DefaultPropagationMaxAge)
	require.NoError(t, err)
	assert.Equal(t, "key-123", keyID)

	// Wait for headers to expire (simulate time passing with short max age)
	shortMaxAge := 100 * time.Millisecond
	time.Sleep(150 * time.Millisecond)

	// Replay with same headers should fail
	req2, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set(HeaderAPIKeyID, "key-123")
	req2.Header.Set(HeaderAPIKeyName, "test-key")
	req2.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))
	req2.Header.Set(HeaderAPIKeyTimestamp, timestamp)
	req2.Header.Set(HeaderAPIKeySignature, signature)

	_, _, _, err = VerifyAndExtractPropagatedKeyFromRequest(req2, secret, shortMaxAge)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "propagation headers expired")
}
