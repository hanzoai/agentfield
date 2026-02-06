package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type stubAgentResolverStorage struct {
	agent *types.AgentNode
	err   error
}

func (s *stubAgentResolverStorage) GetAgent(_ context.Context, _ string) (*types.AgentNode, error) {
	return s.agent, s.err
}

type stubDIDResolver struct{}

func (r *stubDIDResolver) GenerateDIDWeb(agentID string) string {
	return "did:web:localhost%3A8080:agents:" + agentID
}

func TestCheckPermission_RejectsMissingTargetContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewPermissionHandlers(nil, nil, nil)
	router.GET("/api/v1/permissions/check", handler.CheckPermission)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/permissions/check?caller_did=did:web:a&target_did=did:web:b", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "target_agent_id")
}

func TestCheckPermission_RejectsUnresolvableTargetContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewPermissionHandlers(nil, &stubAgentResolverStorage{agent: nil}, &stubDIDResolver{})
	router.GET("/api/v1/permissions/check", handler.CheckPermission)

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/permissions/check?caller_did=did:web:a&target_did=did:web:b&target_agent_id=missing",
		nil,
	)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_target_context")
}

func TestCheckPermission_RejectsTargetContextMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewPermissionHandlers(nil, &stubAgentResolverStorage{
		agent: &types.AgentNode{ID: "target-a"},
	}, &stubDIDResolver{})
	router.GET("/api/v1/permissions/check", handler.CheckPermission)

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/permissions/check?caller_did=did:web:a&target_agent_id=target-a&target_did=did:web:wrong",
		nil,
	)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "target_context_mismatch")
}
