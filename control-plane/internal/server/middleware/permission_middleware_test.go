package middleware

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type testPermissionService struct {
	checkFn       func(ctx context.Context, callerDID, targetDID string, targetAgentID string, targetTags []string) (*types.PermissionCheck, error)
	requestFn     func(ctx context.Context, req *types.PermissionRequest) (*types.PermissionApproval, error)
	isEnabled     bool
	protectedTags map[string]struct{}
}

func (s *testPermissionService) IsEnabled() bool {
	return s.isEnabled
}

func (s *testPermissionService) IsAgentProtected(_ string, tags []string) bool {
	for _, tag := range tags {
		if _, ok := s.protectedTags[tag]; ok {
			return true
		}
	}
	return false
}

func (s *testPermissionService) CheckPermission(ctx context.Context, callerDID, targetDID string, targetAgentID string, targetTags []string) (*types.PermissionCheck, error) {
	if s.checkFn != nil {
		return s.checkFn(ctx, callerDID, targetDID, targetAgentID, targetTags)
	}
	return &types.PermissionCheck{
		RequiresPermission: true,
		HasValidApproval:   true,
	}, nil
}

func (s *testPermissionService) RequestPermission(ctx context.Context, req *types.PermissionRequest) (*types.PermissionApproval, error) {
	if s.requestFn != nil {
		return s.requestFn(ctx, req)
	}
	return nil, nil
}

type testAgentResolver struct{}

func (r *testAgentResolver) GetAgent(_ context.Context, agentID string) (*types.AgentNode, error) {
	switch agentID {
	case "protected-agent":
		return &types.AgentNode{
			ID: agentID,
			Metadata: types.AgentMetadata{
				Deployment: &types.DeploymentMetadata{
					Tags: map[string]string{"role": "admin"},
				},
			},
		}, nil
	default:
		return &types.AgentNode{
			ID: agentID,
			Metadata: types.AgentMetadata{
				Deployment: &types.DeploymentMetadata{
					Tags: map[string]string{"role": "public"},
				},
			},
		}, nil
	}
}

type failingAgentResolver struct{}

func (r *failingAgentResolver) GetAgent(_ context.Context, _ string) (*types.AgentNode, error) {
	return nil, fmt.Errorf("storage unavailable")
}

type testDIDResolver struct{}

func (r *testDIDResolver) GenerateDIDWeb(agentID string) string {
	return "did:web:localhost%3A8080:agents:" + agentID
}

func (r *testDIDResolver) ResolveAgentIDByDID(_ context.Context, _ string) string {
	return ""
}

type testDIDWebService struct {
	publicKeys map[string]ed25519.PublicKey
}

func (s *testDIDWebService) VerifyDIDOwnership(_ context.Context, did string, message []byte, signature []byte) (bool, error) {
	pub, ok := s.publicKeys[did]
	if !ok {
		return false, fmt.Errorf("did not found")
	}
	return ed25519.Verify(pub, message, signature), nil
}

func signRequestBody(body []byte, did string, privateKey ed25519.PrivateKey, ts time.Time) (map[string]string, error) {
	timestamp := fmt.Sprintf("%d", ts.Unix())
	bodyHash := sha256.Sum256(body)
	payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
	signature := ed25519.Sign(privateKey, []byte(payload))
	return map[string]string{
		"X-Caller-DID":    did,
		"X-DID-Signature": base64.StdEncoding.EncodeToString(signature),
		"X-DID-Timestamp": timestamp,
	}, nil
}

func setupProtectedRoute(permissionService PermissionServiceInterface, didService DIDWebServiceInterface, resolver AgentResolverInterface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(DIDAuthMiddleware(didService, DIDAuthConfig{
		Enabled:                true,
		TimestampWindowSeconds: 300,
	}))
	if resolver == nil {
		resolver = &testAgentResolver{}
	}
	router.Use(PermissionCheckMiddleware(
		permissionService,
		resolver,
		&testDIDResolver{},
		PermissionConfig{Enabled: true},
	))
	router.POST("/api/v1/execute/:target", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

func TestProtectedRoute_WithoutDIDDenied(t *testing.T) {
	perm := &testPermissionService{
		isEnabled:     true,
		protectedTags: map[string]struct{}{"admin": {}},
	}
	router := setupProtectedRoute(perm, &testDIDWebService{publicKeys: map[string]ed25519.PublicKey{}}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/protected-agent.reasoner", bytes.NewReader([]byte(`{"x":1}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "did_auth_required")
}

func TestProtectedRoute_InvalidOrExpiredSignatureDenied(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	did := "did:web:localhost%3A8080:agents:caller"
	didService := &testDIDWebService{publicKeys: map[string]ed25519.PublicKey{did: publicKey}}
	perm := &testPermissionService{
		isEnabled:     true,
		protectedTags: map[string]struct{}{"admin": {}},
	}
	router := setupProtectedRoute(perm, didService, nil)

	body := []byte(`{"x":1}`)

	t.Run("invalid signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/protected-agent.reasoner", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString([]byte("invalid")))
		req.Header.Set("X-DID-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("expired timestamp", func(t *testing.T) {
		headers, _ := signRequestBody(body, did, privateKey, time.Now().Add(-10*time.Minute))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/protected-agent.reasoner", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestProtectedRoute_PermissionBackendErrorDenied(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	did := "did:web:localhost%3A8080:agents:caller"
	didService := &testDIDWebService{publicKeys: map[string]ed25519.PublicKey{did: publicKey}}
	perm := &testPermissionService{
		isEnabled:     true,
		protectedTags: map[string]struct{}{"admin": {}},
		checkFn: func(context.Context, string, string, string, []string) (*types.PermissionCheck, error) {
			return nil, fmt.Errorf("storage unavailable")
		},
	}
	router := setupProtectedRoute(perm, didService, nil)

	body := []byte(`{"x":1}`)
	headers, _ := signRequestBody(body, did, privateKey, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/protected-agent.reasoner", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "permission_check_failed")
}

func TestUnprotectedRoute_WithoutDIDStillWorks(t *testing.T) {
	perm := &testPermissionService{
		isEnabled:     true,
		protectedTags: map[string]struct{}{"admin": {}},
	}
	router := setupProtectedRoute(perm, &testDIDWebService{publicKeys: map[string]ed25519.PublicKey{}}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/open-agent.reasoner", bytes.NewReader([]byte(`{"x":1}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestProtectedRoute_TargetResolutionErrorDenied(t *testing.T) {
	perm := &testPermissionService{
		isEnabled:     true,
		protectedTags: map[string]struct{}{"admin": {}},
	}
	router := setupProtectedRoute(perm, &testDIDWebService{publicKeys: map[string]ed25519.PublicKey{}}, &failingAgentResolver{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/execute/protected-agent.reasoner", bytes.NewReader([]byte(`{"x":1}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "target_resolution_failed")
}
