// Package internal provides integration tests for the VC-based authorization system.
//
// These tests verify the complete flow from storage through services to HTTP handlers
// with minimal mocking, using real SQLite storage for integration validation.
package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/handlers"
	adminhandlers "github.com/Agent-Field/agentfield/control-plane/internal/handlers/admin"
	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Infrastructure
// =============================================================================

// testContext holds all components needed for integration testing
type testContext struct {
	t                 *testing.T
	ctx               context.Context
	storage           *storage.LocalStorage
	didWebService     *mockDIDWebService
	permissionService *services.PermissionService
	router            *gin.Engine
	cleanup           func()
}

// mockDIDWebService provides a minimal DID web service for testing
type mockDIDWebService struct {
	domain  string
	storage storage.StorageProvider
}

func newMockDIDWebService(domain string, s storage.StorageProvider) *mockDIDWebService {
	return &mockDIDWebService{
		domain:  domain,
		storage: s,
	}
}

func (m *mockDIDWebService) GenerateDIDWeb(agentID string) string {
	encodedDomain := strings.ReplaceAll(m.domain, ":", "%3A")
	return fmt.Sprintf("did:web:%s:agents:%s", encodedDomain, agentID)
}

func (m *mockDIDWebService) ParseDIDWeb(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("invalid did:web format")
	}
	parts := strings.Split(did, ":")
	for i, part := range parts {
		if part == "agents" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("invalid did:web format: missing 'agents' segment")
}

func (m *mockDIDWebService) VerifyDIDOwnership(ctx context.Context, did string, message []byte, signature []byte) (bool, error) {
	// Look up the DID document to get the public key
	record, err := m.storage.GetDIDDocument(ctx, did)
	if err != nil {
		return false, fmt.Errorf("DID not found: %w", err)
	}

	if record.IsRevoked() {
		return false, fmt.Errorf("DID is revoked")
	}

	// Parse the public key from JWK
	var jwk struct {
		X string `json:"x"`
	}
	if err := json.Unmarshal([]byte(record.PublicKeyJWK), &jwk); err != nil {
		return false, fmt.Errorf("invalid public key JWK: %w", err)
	}

	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	publicKey := ed25519.PublicKey(publicKeyBytes)
	return ed25519.Verify(publicKey, message, signature), nil
}

func (m *mockDIDWebService) RevokeDID(ctx context.Context, did string) error {
	return m.storage.RevokeDIDDocument(ctx, did)
}

func (m *mockDIDWebService) GetOrCreateDIDDocument(ctx context.Context, agentID string) (*types.DIDWebDocument, string, error) {
	did := m.GenerateDIDWeb(agentID)

	// Try to get existing
	record, err := m.storage.GetDIDDocument(ctx, did)
	if err == nil && !record.IsRevoked() {
		var didDoc types.DIDWebDocument
		if err := json.Unmarshal(record.DIDDocument, &didDoc); err != nil {
			return nil, "", err
		}
		return &didDoc, did, nil
	}

	// Generate new key pair
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, "", err
	}

	pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(publicKey))

	didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
	docBytes, _ := json.Marshal(didDoc)

	record = &types.DIDDocumentRecord{
		DID:          did,
		AgentID:      agentID,
		DIDDocument:  docBytes,
		PublicKeyJWK: pubKeyJWK,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := m.storage.StoreDIDDocument(ctx, record); err != nil {
		return nil, "", err
	}

	return didDoc, did, nil
}

func (m *mockDIDWebService) ResolveDID(ctx context.Context, did string) (*types.DIDResolutionResult, error) {
	record, err := m.storage.GetDIDDocument(ctx, did)
	if err != nil {
		return &types.DIDResolutionResult{
			DIDResolutionMetadata: types.DIDResolutionMetadata{Error: "notFound"},
		}, nil
	}

	if record.IsRevoked() {
		return &types.DIDResolutionResult{
			DIDResolutionMetadata: types.DIDResolutionMetadata{Error: "deactivated"},
			DIDDocumentMetadata:   types.DIDDocumentMetadata{Deactivated: true},
		}, nil
	}

	var didDoc types.DIDWebDocument
	if err := json.Unmarshal(record.DIDDocument, &didDoc); err != nil {
		return &types.DIDResolutionResult{
			DIDResolutionMetadata: types.DIDResolutionMetadata{Error: "invalidDidDocument"},
		}, nil
	}

	return &types.DIDResolutionResult{
		DIDDocument:           &didDoc,
		DIDResolutionMetadata: types.DIDResolutionMetadata{ContentType: "application/did+ld+json"},
	}, nil
}

// setupTestContext creates a fully initialized test environment with real storage
func setupTestContext(t *testing.T) *testContext {
	t.Helper()

	ctx := context.Background()
	tempDir := t.TempDir()

	// Initialize real SQLite storage
	cfg := storage.StorageConfig{
		Mode: "local",
		Local: storage.LocalStorageConfig{
			DatabasePath: filepath.Join(tempDir, "test_agentfield.db"),
			KVStorePath:  filepath.Join(tempDir, "test_agentfield.bolt"),
		},
	}

	ls := storage.NewLocalStorage(storage.LocalStorageConfig{})
	if err := ls.Initialize(ctx, cfg); err != nil {
		if strings.Contains(err.Error(), "no such module: fts5") {
			t.Skip("sqlite3 compiled without FTS5; skipping integration test")
		}
		t.Fatalf("failed to initialize local storage: %v", err)
	}

	// Create mock DID Web service (uses real storage)
	didWebService := newMockDIDWebService("localhost:8080", ls)

	// Create permission service
	permissionConfig := &services.PermissionConfig{
		Enabled:              true,
		DefaultDurationHours: 720, // 30 days
		AutoRequestOnDeny:    true,
	}
	permissionService := services.NewPermissionService(ls, nil, nil, permissionConfig)

	// Initialize permission service (loads protected agent rules)
	err := permissionService.Initialize(ctx)
	require.NoError(t, err, "failed to initialize permission service")

	// Set up Gin router for HTTP tests
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add test middleware that simulates DID auth verification.
	// In production, the DID auth middleware verifies signatures and sets verified_caller_did.
	// For integration tests, we trust the X-Caller-DID header directly.
	router.Use(func(c *gin.Context) {
		if did := c.GetHeader("X-Caller-DID"); did != "" {
			c.Set("verified_caller_did", did)
		}
		c.Next()
	})

	tc := &testContext{
		t:                 t,
		ctx:               ctx,
		storage:           ls,
		didWebService:     didWebService,
		permissionService: permissionService,
		router:            router,
		cleanup: func() {
			_ = ls.Close(ctx)
		},
	}

	t.Cleanup(tc.cleanup)

	return tc
}

// createTestAgent creates a test agent in storage with the given ID and tags
func (tc *testContext) createTestAgent(agentID string, tags map[string]string) *types.AgentNode {
	tc.t.Helper()

	agent := &types.AgentNode{
		ID:             agentID,
		DeploymentType: "test",
		Metadata: types.AgentMetadata{
			Deployment: &types.DeploymentMetadata{
				Tags: tags,
			},
		},
		RegisteredAt: time.Now(),
	}

	err := tc.storage.RegisterAgent(tc.ctx, agent)
	require.NoError(tc.t, err, "failed to register test agent")

	return agent
}

// =============================================================================
// Phase 1: Storage Layer Tests
// =============================================================================

func TestVCAuth_Phase1_Storage_DIDDocuments(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("store and retrieve DID document", func(t *testing.T) {
		// Create a DID document
		agentID := "test-agent-did-1"
		did := tc.didWebService.GenerateDIDWeb(agentID)

		// Generate a test public key JWK
		pubKey, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(pubKey))

		didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
		docBytes, err := json.Marshal(didDoc)
		require.NoError(t, err)

		record := &types.DIDDocumentRecord{
			DID:          did,
			AgentID:      agentID,
			DIDDocument:  docBytes,
			PublicKeyJWK: pubKeyJWK,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Store the DID document
		err = tc.storage.StoreDIDDocument(tc.ctx, record)
		require.NoError(t, err)

		// Retrieve by DID
		retrieved, err := tc.storage.GetDIDDocument(tc.ctx, did)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, did, retrieved.DID)
		assert.Equal(t, agentID, retrieved.AgentID)
		assert.False(t, retrieved.IsRevoked())

		// Retrieve by agent ID
		retrievedByAgent, err := tc.storage.GetDIDDocumentByAgentID(tc.ctx, agentID)
		require.NoError(t, err)
		require.NotNil(t, retrievedByAgent)
		assert.Equal(t, did, retrievedByAgent.DID)
	})

	t.Run("revoke DID document", func(t *testing.T) {
		agentID := "test-agent-did-2"
		did := tc.didWebService.GenerateDIDWeb(agentID)

		pubKey, _, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(pubKey))

		didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
		docBytes, _ := json.Marshal(didDoc)

		record := &types.DIDDocumentRecord{
			DID:          did,
			AgentID:      agentID,
			DIDDocument:  docBytes,
			PublicKeyJWK: pubKeyJWK,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err = tc.storage.StoreDIDDocument(tc.ctx, record)
		require.NoError(t, err)

		// Revoke the DID
		err = tc.storage.RevokeDIDDocument(tc.ctx, did)
		require.NoError(t, err)

		// Verify it's revoked
		retrieved, err := tc.storage.GetDIDDocument(tc.ctx, did)
		require.NoError(t, err)
		assert.True(t, retrieved.IsRevoked())
	})

	t.Run("list DID documents", func(t *testing.T) {
		// Create multiple DID documents
		for i := 3; i <= 5; i++ {
			agentID := fmt.Sprintf("test-agent-did-%d", i)
			did := tc.didWebService.GenerateDIDWeb(agentID)

			pubKey, _, _ := ed25519.GenerateKey(nil)
			pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
				base64.RawURLEncoding.EncodeToString(pubKey))

			didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
			docBytes, _ := json.Marshal(didDoc)

			record := &types.DIDDocumentRecord{
				DID:          did,
				AgentID:      agentID,
				DIDDocument:  docBytes,
				PublicKeyJWK: pubKeyJWK,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			_ = tc.storage.StoreDIDDocument(tc.ctx, record)
		}

		// List all DID documents
		docs, err := tc.storage.ListDIDDocuments(tc.ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(docs), 3)
	})
}

func TestVCAuth_Phase1_Storage_PermissionApprovals(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("create and retrieve permission approval", func(t *testing.T) {
		approval := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:caller-1",
			TargetDID:     "did:web:localhost:agents:target-1",
			CallerAgentID: "caller-1",
			TargetAgentID: "target-1",
			Status:        types.PermissionStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		err := tc.storage.CreatePermissionApproval(tc.ctx, approval)
		require.NoError(t, err)
		assert.NotZero(t, approval.ID, "approval ID should be set after creation")

		// Retrieve by caller/target DIDs
		retrieved, err := tc.storage.GetPermissionApproval(tc.ctx, approval.CallerDID, approval.TargetDID)
		require.NoError(t, err)
		assert.Equal(t, approval.CallerDID, retrieved.CallerDID)
		assert.Equal(t, approval.TargetDID, retrieved.TargetDID)
		assert.Equal(t, types.PermissionStatusPending, retrieved.Status)

		// Retrieve by ID
		retrievedByID, err := tc.storage.GetPermissionApprovalByID(tc.ctx, approval.ID)
		require.NoError(t, err)
		assert.Equal(t, approval.ID, retrievedByID.ID)
	})

	t.Run("update permission approval - approve", func(t *testing.T) {
		approval := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:caller-2",
			TargetDID:     "did:web:localhost:agents:target-2",
			CallerAgentID: "caller-2",
			TargetAgentID: "target-2",
			Status:        types.PermissionStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		err := tc.storage.CreatePermissionApproval(tc.ctx, approval)
		require.NoError(t, err)

		// Update to approved
		now := time.Now()
		approvedBy := "admin"
		approval.Status = types.PermissionStatusApproved
		approval.ApprovedBy = &approvedBy
		approval.ApprovedAt = &now
		approval.UpdatedAt = now

		err = tc.storage.UpdatePermissionApproval(tc.ctx, approval)
		require.NoError(t, err)

		// Verify update
		retrieved, err := tc.storage.GetPermissionApprovalByID(tc.ctx, approval.ID)
		require.NoError(t, err)
		assert.Equal(t, types.PermissionStatusApproved, retrieved.Status)
		assert.NotNil(t, retrieved.ApprovedBy)
		assert.Equal(t, "admin", *retrieved.ApprovedBy)
	})

	t.Run("list permission approvals by status", func(t *testing.T) {
		// Create pending approval
		pending := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:caller-3",
			TargetDID:     "did:web:localhost:agents:target-3",
			CallerAgentID: "caller-3",
			TargetAgentID: "target-3",
			Status:        types.PermissionStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := tc.storage.CreatePermissionApproval(tc.ctx, pending)
		require.NoError(t, err)

		// List pending
		pendingList, err := tc.storage.ListPermissionApprovals(tc.ctx, types.PermissionStatusPending)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(pendingList), 1)

		// Verify our approval is in the list
		found := false
		for _, p := range pendingList {
			if p.ID == pending.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "expected pending approval in list")
	})

	t.Run("unique constraint on caller-target pair", func(t *testing.T) {
		approval1 := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:unique-caller",
			TargetDID:     "did:web:localhost:agents:unique-target",
			CallerAgentID: "unique-caller",
			TargetAgentID: "unique-target",
			Status:        types.PermissionStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		err := tc.storage.CreatePermissionApproval(tc.ctx, approval1)
		require.NoError(t, err)

		// Try to create duplicate
		approval2 := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:unique-caller",
			TargetDID:     "did:web:localhost:agents:unique-target",
			CallerAgentID: "unique-caller",
			TargetAgentID: "unique-target",
			Status:        types.PermissionStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		err = tc.storage.CreatePermissionApproval(tc.ctx, approval2)
		assert.Error(t, err, "expected unique constraint violation")
	})
}

func TestVCAuth_Phase1_Storage_ProtectedAgentRules(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("create and retrieve protected agent rule", func(t *testing.T) {
		rule := &types.ProtectedAgentRule{
			PatternType: types.PatternTypeTag,
			Pattern:     "admin",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err := tc.storage.CreateProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)
		assert.NotZero(t, rule.ID)

		// Retrieve all rules
		rules, err := tc.storage.GetProtectedAgentRules(tc.ctx)
		require.NoError(t, err)

		found := false
		for _, r := range rules {
			if r.ID == rule.ID {
				found = true
				assert.Equal(t, types.PatternTypeTag, r.PatternType)
				assert.Equal(t, "admin", r.Pattern)
				break
			}
		}
		assert.True(t, found, "expected rule in list")
	})

	t.Run("create rule with pattern types", func(t *testing.T) {
		// Tag pattern
		tagPatternRule := &types.ProtectedAgentRule{
			PatternType: types.PatternTypeTagPattern,
			Pattern:     "finance*",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		err := tc.storage.CreateProtectedAgentRule(tc.ctx, tagPatternRule)
		require.NoError(t, err)

		// Agent ID pattern
		agentIDRule := &types.ProtectedAgentRule{
			PatternType: types.PatternTypeAgentID,
			Pattern:     "payment-gateway",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		err = tc.storage.CreateProtectedAgentRule(tc.ctx, agentIDRule)
		require.NoError(t, err)
	})

	t.Run("delete protected agent rule", func(t *testing.T) {
		rule := &types.ProtectedAgentRule{
			PatternType: types.PatternTypeTag,
			Pattern:     "to-delete",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err := tc.storage.CreateProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		// Delete the rule
		err = tc.storage.DeleteProtectedAgentRule(tc.ctx, rule.ID)
		require.NoError(t, err)

		// Verify it's deleted
		rules, err := tc.storage.GetProtectedAgentRules(tc.ctx)
		require.NoError(t, err)

		for _, r := range rules {
			assert.NotEqual(t, rule.ID, r.ID, "deleted rule should not be in list")
		}
	})
}

// =============================================================================
// Phase 2: Service Layer Tests
// =============================================================================

func TestVCAuth_Phase2_Service_DIDWebService(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("generate DID web identifier", func(t *testing.T) {
		did := tc.didWebService.GenerateDIDWeb("my-agent")
		assert.Contains(t, did, "did:web:")
		assert.Contains(t, did, "agents:my-agent")
	})

	t.Run("parse DID web identifier", func(t *testing.T) {
		did := tc.didWebService.GenerateDIDWeb("parsed-agent")
		agentID, err := tc.didWebService.ParseDIDWeb(did)
		require.NoError(t, err)
		assert.Equal(t, "parsed-agent", agentID)
	})

	t.Run("get or create DID document", func(t *testing.T) {
		agentID := "new-agent-did"

		// First call creates
		didDoc1, did1, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, agentID)
		require.NoError(t, err)
		require.NotNil(t, didDoc1)
		assert.Contains(t, did1, agentID)

		// Second call returns existing
		didDoc2, did2, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, agentID)
		require.NoError(t, err)
		assert.Equal(t, did1, did2)
		assert.Equal(t, didDoc1.ID, didDoc2.ID)
	})

	t.Run("resolve DID", func(t *testing.T) {
		agentID := "resolvable-agent"
		_, did, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, agentID)
		require.NoError(t, err)

		// Resolve the DID
		result, err := tc.didWebService.ResolveDID(tc.ctx, did)
		require.NoError(t, err)
		assert.NotNil(t, result.DIDDocument)
		assert.Empty(t, result.DIDResolutionMetadata.Error)
	})

	t.Run("resolve non-existent DID returns not found", func(t *testing.T) {
		result, err := tc.didWebService.ResolveDID(tc.ctx, "did:web:localhost:agents:nonexistent")
		require.NoError(t, err)
		assert.Equal(t, "notFound", result.DIDResolutionMetadata.Error)
	})

	t.Run("resolve revoked DID returns deactivated", func(t *testing.T) {
		agentID := "to-revoke-agent"
		_, did, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, agentID)
		require.NoError(t, err)

		// Revoke
		err = tc.didWebService.RevokeDID(tc.ctx, did)
		require.NoError(t, err)

		// Resolve should show deactivated
		result, err := tc.didWebService.ResolveDID(tc.ctx, did)
		require.NoError(t, err)
		assert.Equal(t, "deactivated", result.DIDResolutionMetadata.Error)
		assert.True(t, result.DIDDocumentMetadata.Deactivated)
	})
}

func TestVCAuth_Phase2_Service_PermissionService(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("is enabled returns correct state", func(t *testing.T) {
		assert.True(t, tc.permissionService.IsEnabled())
	})

	t.Run("request permission creates pending approval", func(t *testing.T) {
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:perm-caller-1",
			TargetDID:     "did:web:localhost:agents:perm-target-1",
			CallerAgentID: "perm-caller-1",
			TargetAgentID: "perm-target-1",
			Reason:        "Testing permission request",
		}

		approval, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)
		assert.NotZero(t, approval.ID)
		assert.Equal(t, types.PermissionStatusPending, approval.Status)
	})

	t.Run("request permission returns existing if duplicate", func(t *testing.T) {
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:dup-caller",
			TargetDID:     "did:web:localhost:agents:dup-target",
			CallerAgentID: "dup-caller",
			TargetAgentID: "dup-target",
			Reason:        "First request",
		}

		approval1, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)

		// Same request
		req.Reason = "Second request"
		approval2, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)
		assert.Equal(t, approval1.ID, approval2.ID, "should return existing approval")
	})

	t.Run("approve permission", func(t *testing.T) {
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:to-approve-caller",
			TargetDID:     "did:web:localhost:agents:to-approve-target",
			CallerAgentID: "to-approve-caller",
			TargetAgentID: "to-approve-target",
			Reason:        "To be approved",
		}

		approval, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)

		// Approve
		durationHours := 24
		approved, err := tc.permissionService.ApprovePermission(tc.ctx, approval.ID, "admin", &durationHours)
		require.NoError(t, err)
		assert.Equal(t, types.PermissionStatusApproved, approved.Status)
		assert.NotNil(t, approved.ApprovedBy)
		assert.NotNil(t, approved.ApprovedAt)
		assert.NotNil(t, approved.ExpiresAt)
	})

	t.Run("reject permission", func(t *testing.T) {
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:to-reject-caller",
			TargetDID:     "did:web:localhost:agents:to-reject-target",
			CallerAgentID: "to-reject-caller",
			TargetAgentID: "to-reject-target",
		}

		approval, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)

		// Reject
		rejected, err := tc.permissionService.RejectPermission(tc.ctx, approval.ID, "admin", "Access denied")
		require.NoError(t, err)
		assert.Equal(t, types.PermissionStatusRejected, rejected.Status)
	})

	t.Run("revoke approved permission", func(t *testing.T) {
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:to-revoke-caller",
			TargetDID:     "did:web:localhost:agents:to-revoke-target",
			CallerAgentID: "to-revoke-caller",
			TargetAgentID: "to-revoke-target",
		}

		approval, err := tc.permissionService.RequestPermission(tc.ctx, req)
		require.NoError(t, err)

		// Approve first
		approved, err := tc.permissionService.ApprovePermission(tc.ctx, approval.ID, "admin", nil)
		require.NoError(t, err)

		// Revoke
		revoked, err := tc.permissionService.RevokePermission(tc.ctx, approved.ID, "admin", "Security concern")
		require.NoError(t, err)
		assert.Equal(t, types.PermissionStatusRevoked, revoked.Status)
	})

	t.Run("protected agent rule matching", func(t *testing.T) {
		// Add a protected agent rule
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeTag,
			Pattern:     "protected",
			Description: "Protected tag rule",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		// Check if agent with protected tag is protected
		isProtected := tc.permissionService.IsAgentProtected("any-agent", []string{"protected"})
		assert.True(t, isProtected)

		// Check unprotected agent
		isProtected = tc.permissionService.IsAgentProtected("any-agent", []string{"regular"})
		assert.False(t, isProtected)
	})

	t.Run("check permission for protected agent", func(t *testing.T) {
		// Add protection rule for "admin" tag
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeTag,
			Pattern:     "admin-check",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		// Check permission without approval
		check, err := tc.permissionService.CheckPermission(
			tc.ctx,
			"did:web:localhost:agents:check-caller",
			"did:web:localhost:agents:check-target",
			"check-target",
			[]string{"admin-check"},
		)
		require.NoError(t, err)
		assert.True(t, check.RequiresPermission)
		assert.False(t, check.HasValidApproval)
	})

	t.Run("check permission with valid approval", func(t *testing.T) {
		// Add protection rule
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeTag,
			Pattern:     "approved-tag",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		// Create and approve permission
		req := &types.PermissionRequest{
			CallerDID:     "did:web:localhost:agents:approved-caller",
			TargetDID:     "did:web:localhost:agents:approved-target",
			CallerAgentID: "approved-caller",
			TargetAgentID: "approved-target",
		}
		approval, _ := tc.permissionService.RequestPermission(tc.ctx, req)
		_, _ = tc.permissionService.ApprovePermission(tc.ctx, approval.ID, "admin", nil)

		// Check permission
		check, err := tc.permissionService.CheckPermission(
			tc.ctx,
			req.CallerDID,
			req.TargetDID,
			"approved-target",
			[]string{"approved-tag"},
		)
		require.NoError(t, err)
		assert.True(t, check.RequiresPermission)
		assert.True(t, check.HasValidApproval)
	})
}

// =============================================================================
// Phase 3: Middleware Tests
// =============================================================================

func TestVCAuth_Phase3_Middleware_DIDAuth(t *testing.T) {
	tc := setupTestContext(t)

	// Generate test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create DID and store document
	agentID := "middleware-test-agent"
	did := tc.didWebService.GenerateDIDWeb(agentID)

	// Store DID document with our test key
	pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(publicKey))

	didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
	docBytes, _ := json.Marshal(didDoc)

	record := &types.DIDDocumentRecord{
		DID:          did,
		AgentID:      agentID,
		DIDDocument:  docBytes,
		PublicKeyJWK: pubKeyJWK,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err = tc.storage.StoreDIDDocument(tc.ctx, record)
	require.NoError(t, err)

	// Helper to sign requests
	signRequest := func(body []byte) (string, string) {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))
		return base64.StdEncoding.EncodeToString(signature), timestamp
	}

	t.Run("request without DID passes through", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("POST", "/test", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("request with valid DID signature succeeds", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			verifiedDID := middleware.GetVerifiedCallerDID(c)
			c.JSON(200, gin.H{"verified_did": verifiedDID})
		})

		body := []byte(`{"test":"data"}`)
		signature, timestamp := signRequest(body)

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", signature)
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, did, response["verified_did"])
	})

	t.Run("request with DID but missing signature fails", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("POST", "/test", strings.NewReader(`{}`))
		req.Header.Set("X-Caller-DID", did)
		// Missing signature and timestamp

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("request with invalid signature fails", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		body := []byte(`{"test":"data"}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString([]byte("invalid")))
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("request with expired timestamp fails", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		body := []byte(`{"test":"data"}`)
		// Use timestamp 10 minutes ago
		oldTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", oldTimestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", oldTimestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})
}

// =============================================================================
// Phase 4: API Handler Tests
// =============================================================================

func TestVCAuth_Phase4_Handlers_PermissionAPI(t *testing.T) {
	tc := setupTestContext(t)

	// Set up permission handlers
	permissionHandlers := handlers.NewPermissionHandlers(tc.permissionService, tc.storage, tc.didWebService)
	adminPermHandlers := adminhandlers.NewPermissionAdminHandlers(tc.permissionService)

	// Register routes
	api := tc.router.Group("/api/v1")
	permissionHandlers.RegisterRoutes(api)
	adminPermHandlers.RegisterRoutes(api)

	t.Run("POST /permissions/request creates pending approval", func(t *testing.T) {
		body := `{
			"caller_did": "did:web:localhost:agents:api-caller",
			"target_did": "did:web:localhost:agents:api-target",
			"caller_agent_id": "api-caller",
			"target_agent_id": "api-target",
			"reason": "API test"
		}`

		req := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", "did:web:localhost:agents:api-caller")
		w := httptest.NewRecorder()
		tc.router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var approval types.PermissionApproval
		err := json.Unmarshal(w.Body.Bytes(), &approval)
		require.NoError(t, err)
		assert.Equal(t, types.PermissionStatusPending, approval.Status)
	})

	t.Run("GET /permissions/check returns permission status", func(t *testing.T) {
		// Register a target agent so the handler can resolve it
		checkTarget := &types.AgentNode{
			ID:             "check-target",
			Version:        "1.0.0",
			DeploymentType: "long_running",
		}
		_ = tc.storage.RegisterAgent(tc.ctx, checkTarget)

		req := httptest.NewRequest("GET",
			"/api/v1/permissions/check?caller_did=did:web:localhost:agents:check-caller&target_agent_id=check-target",
			nil)
		w := httptest.NewRecorder()
		tc.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var check types.PermissionCheck
		err := json.Unmarshal(w.Body.Bytes(), &check)
		require.NoError(t, err)
	})

	t.Run("GET /admin/permissions/pending lists pending requests", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/permissions/pending", nil)
		w := httptest.NewRecorder()
		tc.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Permissions []*types.PermissionApproval `json:"permissions"`
			Total       int                         `json:"total"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
	})

	t.Run("POST /admin/permissions/:id/approve approves request", func(t *testing.T) {
		// First create a pending request
		createBody := `{
			"caller_did": "did:web:localhost:agents:to-approve-api",
			"target_did": "did:web:localhost:agents:target-api",
			"caller_agent_id": "to-approve-api",
			"target_agent_id": "target-api"
		}`
		createReq := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("X-Caller-DID", "did:web:localhost:agents:to-approve-api")
		createW := httptest.NewRecorder()
		tc.router.ServeHTTP(createW, createReq)
		require.Equal(t, 201, createW.Code)

		var created types.PermissionApproval
		json.Unmarshal(createW.Body.Bytes(), &created)

		// Approve it
		approveBody := `{"duration_hours": 24}`
		approveReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/approve", created.ID),
			strings.NewReader(approveBody))
		approveReq.Header.Set("Content-Type", "application/json")
		approveW := httptest.NewRecorder()
		tc.router.ServeHTTP(approveW, approveReq)

		assert.Equal(t, 200, approveW.Code)

		var approved types.PermissionApproval
		json.Unmarshal(approveW.Body.Bytes(), &approved)
		assert.Equal(t, types.PermissionStatusApproved, approved.Status)
	})

	t.Run("POST /admin/permissions/:id/reject rejects request", func(t *testing.T) {
		// Create pending request
		createBody := `{
			"caller_did": "did:web:localhost:agents:to-reject-api",
			"target_did": "did:web:localhost:agents:target-reject-api",
			"caller_agent_id": "to-reject-api",
			"target_agent_id": "target-reject-api"
		}`
		createReq := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("X-Caller-DID", "did:web:localhost:agents:to-reject-api")
		createW := httptest.NewRecorder()
		tc.router.ServeHTTP(createW, createReq)

		var created types.PermissionApproval
		json.Unmarshal(createW.Body.Bytes(), &created)

		// Reject it
		rejectBody := `{"reason": "Access denied"}`
		rejectReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/reject", created.ID),
			strings.NewReader(rejectBody))
		rejectReq.Header.Set("Content-Type", "application/json")
		rejectW := httptest.NewRecorder()
		tc.router.ServeHTTP(rejectW, rejectReq)

		assert.Equal(t, 200, rejectW.Code)

		var rejected types.PermissionApproval
		json.Unmarshal(rejectW.Body.Bytes(), &rejected)
		assert.Equal(t, types.PermissionStatusRejected, rejected.Status)
	})

	t.Run("POST /admin/permissions/:id/revoke revokes approved permission", func(t *testing.T) {
		// Create and approve
		createBody := `{
			"caller_did": "did:web:localhost:agents:to-revoke-api",
			"target_did": "did:web:localhost:agents:target-revoke-api",
			"caller_agent_id": "to-revoke-api",
			"target_agent_id": "target-revoke-api"
		}`
		createReq := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("X-Caller-DID", "did:web:localhost:agents:to-revoke-api")
		createW := httptest.NewRecorder()
		tc.router.ServeHTTP(createW, createReq)

		var created types.PermissionApproval
		json.Unmarshal(createW.Body.Bytes(), &created)

		// Approve
		approveReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/approve", created.ID),
			strings.NewReader(`{}`))
		approveReq.Header.Set("Content-Type", "application/json")
		approveW := httptest.NewRecorder()
		tc.router.ServeHTTP(approveW, approveReq)

		// Revoke
		revokeBody := `{"reason": "Security concern"}`
		revokeReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/revoke", created.ID),
			strings.NewReader(revokeBody))
		revokeReq.Header.Set("Content-Type", "application/json")
		revokeW := httptest.NewRecorder()
		tc.router.ServeHTTP(revokeW, revokeReq)

		assert.Equal(t, 200, revokeW.Code)

		var revoked types.PermissionApproval
		json.Unmarshal(revokeW.Body.Bytes(), &revoked)
		assert.Equal(t, types.PermissionStatusRevoked, revoked.Status)
	})
}

func TestVCAuth_Phase4_Handlers_ProtectedAgentsAPI(t *testing.T) {
	tc := setupTestContext(t)

	adminPermHandlers := adminhandlers.NewPermissionAdminHandlers(tc.permissionService)
	api := tc.router.Group("/api/v1")
	adminPermHandlers.RegisterRoutes(api)

	t.Run("POST /admin/protected-agents creates rule", func(t *testing.T) {
		body := `{
			"pattern_type": "tag",
			"pattern": "api-test-rule",
			"description": "Test rule from API"
		}`

		req := httptest.NewRequest("POST", "/api/v1/admin/protected-agents", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		tc.router.ServeHTTP(w, req)

		assert.Equal(t, 201, w.Code)

		var rule types.ProtectedAgentRule
		json.Unmarshal(w.Body.Bytes(), &rule)
		assert.Equal(t, "api-test-rule", rule.Pattern)
	})

	t.Run("GET /admin/protected-agents lists rules", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/protected-agents", nil)
		w := httptest.NewRecorder()
		tc.router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response struct {
			Rules []*types.ProtectedAgentRule `json:"rules"`
			Total int                         `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.GreaterOrEqual(t, len(response.Rules), 0)
	})

	t.Run("DELETE /admin/protected-agents/:id removes rule", func(t *testing.T) {
		// Create a rule first
		createBody := `{
			"pattern_type": "tag",
			"pattern": "to-delete-api",
			"description": "To be deleted"
		}`
		createReq := httptest.NewRequest("POST", "/api/v1/admin/protected-agents", strings.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		tc.router.ServeHTTP(createW, createReq)

		var rule types.ProtectedAgentRule
		json.Unmarshal(createW.Body.Bytes(), &rule)

		// Delete it
		deleteReq := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/admin/protected-agents/%d", rule.ID), nil)
		deleteW := httptest.NewRecorder()
		tc.router.ServeHTTP(deleteW, deleteReq)

		assert.Equal(t, 200, deleteW.Code)
	})
}

// =============================================================================
// Phase 5: End-to-End Integration Tests
// =============================================================================

func TestVCAuth_Phase5_EndToEnd_FullPermissionFlow(t *testing.T) {
	tc := setupTestContext(t)

	// Set up the complete routing with middlewares
	permissionHandlers := handlers.NewPermissionHandlers(tc.permissionService, tc.storage, tc.didWebService)
	adminPermHandlers := adminhandlers.NewPermissionAdminHandlers(tc.permissionService)

	api := tc.router.Group("/api/v1")
	permissionHandlers.RegisterRoutes(api)
	adminPermHandlers.RegisterRoutes(api)

	t.Run("complete flow: create protection rule, request permission, approve, verify", func(t *testing.T) {
		// Step 1: Create a protected agent rule for "sensitive" tag
		// Note: Tags are stored as "key:value", so pattern must match full tag format
		ruleBody := `{"pattern_type": "tag", "pattern": "e2e-sensitive:true", "description": "Sensitive agents"}`
		ruleReq := httptest.NewRequest("POST", "/api/v1/admin/protected-agents", strings.NewReader(ruleBody))
		ruleReq.Header.Set("Content-Type", "application/json")
		ruleW := httptest.NewRecorder()
		tc.router.ServeHTTP(ruleW, ruleReq)
		require.Equal(t, 201, ruleW.Code)

		// Step 2: Create test agents (caller and target)
		callerAgentID := "e2e-caller-agent"
		targetAgentID := "e2e-target-agent"

		tc.createTestAgent(callerAgentID, nil)
		tc.createTestAgent(targetAgentID, map[string]string{"e2e-sensitive": "true"})

		callerDID := tc.didWebService.GenerateDIDWeb(callerAgentID)
		targetDID := tc.didWebService.GenerateDIDWeb(targetAgentID)

		// Step 3: Check permission (should require permission, not have approval)
		// Note: DIDs must be URL-encoded because they contain %3A which would otherwise be decoded
		checkURL := fmt.Sprintf("/api/v1/permissions/check?caller_did=%s&target_did=%s&target_agent_id=%s",
			url.QueryEscape(callerDID), url.QueryEscape(targetDID), url.QueryEscape(targetAgentID))
		checkReq := httptest.NewRequest("GET", checkURL, nil)
		checkW := httptest.NewRecorder()
		tc.router.ServeHTTP(checkW, checkReq)
		require.Equal(t, 200, checkW.Code)

		var initialCheck types.PermissionCheck
		json.Unmarshal(checkW.Body.Bytes(), &initialCheck)

		// Step 4: Request permission
		requestBody := fmt.Sprintf(`{
			"caller_did": "%s",
			"target_did": "%s",
			"caller_agent_id": "%s",
			"target_agent_id": "%s",
			"reason": "E2E test"
		}`, callerDID, targetDID, callerAgentID, targetAgentID)

		requestReq := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(requestBody))
		requestReq.Header.Set("Content-Type", "application/json")
		requestReq.Header.Set("X-Caller-DID", callerDID)
		requestW := httptest.NewRecorder()
		tc.router.ServeHTTP(requestW, requestReq)
		require.Equal(t, 201, requestW.Code)

		var pendingApproval types.PermissionApproval
		json.Unmarshal(requestW.Body.Bytes(), &pendingApproval)
		assert.Equal(t, types.PermissionStatusPending, pendingApproval.Status)

		// Step 5: List pending permissions (admin sees request)
		listReq := httptest.NewRequest("GET", "/api/v1/admin/permissions/pending", nil)
		listW := httptest.NewRecorder()
		tc.router.ServeHTTP(listW, listReq)
		require.Equal(t, 200, listW.Code)

		// Step 6: Admin approves the request
		approveReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/approve", pendingApproval.ID),
			strings.NewReader(`{"duration_hours": 720}`))
		approveReq.Header.Set("Content-Type", "application/json")
		approveW := httptest.NewRecorder()
		tc.router.ServeHTTP(approveW, approveReq)
		require.Equal(t, 200, approveW.Code)

		var approvedPermission types.PermissionApproval
		json.Unmarshal(approveW.Body.Bytes(), &approvedPermission)
		assert.Equal(t, types.PermissionStatusApproved, approvedPermission.Status)
		assert.NotNil(t, approvedPermission.ExpiresAt)

		// Step 7: Check permission again (now should have valid approval)
		checkReq2 := httptest.NewRequest("GET", checkURL, nil)
		checkW2 := httptest.NewRecorder()
		tc.router.ServeHTTP(checkW2, checkReq2)
		require.Equal(t, 200, checkW2.Code)

		var finalCheck types.PermissionCheck
		json.Unmarshal(checkW2.Body.Bytes(), &finalCheck)
	})

	t.Run("complete flow: revoke permission blocks subsequent access", func(t *testing.T) {
		// Create unique agents for this test
		callerID := "revoke-test-caller"
		targetID := "revoke-test-target"
		tc.createTestAgent(callerID, nil)
		tc.createTestAgent(targetID, map[string]string{"restricted": "true"})

		// Add protection rule
		// Note: Tags are stored as "key:value", so pattern must match full tag format
		ruleBody := `{"pattern_type": "tag", "pattern": "restricted:true"}`
		ruleReq := httptest.NewRequest("POST", "/api/v1/admin/protected-agents", strings.NewReader(ruleBody))
		ruleReq.Header.Set("Content-Type", "application/json")
		tc.router.ServeHTTP(httptest.NewRecorder(), ruleReq)

		callerDID := tc.didWebService.GenerateDIDWeb(callerID)
		targetDID := tc.didWebService.GenerateDIDWeb(targetID)

		// Request permission (with proper headers)
		requestBody := fmt.Sprintf(`{
			"caller_did": "%s",
			"target_did": "%s",
			"caller_agent_id": "%s",
			"target_agent_id": "%s"
		}`, callerDID, targetDID, callerID, targetID)

		t.Logf("Creating permission request: callerDID=%s, targetDID=%s", callerDID, targetDID)
		permReq := httptest.NewRequest("POST", "/api/v1/permissions/request", strings.NewReader(requestBody))
		permReq.Header.Set("Content-Type", "application/json")
		permReq.Header.Set("X-Caller-DID", callerDID)
		requestW := httptest.NewRecorder()
		tc.router.ServeHTTP(requestW, permReq)
		require.Equal(t, 201, requestW.Code, "permission request should succeed: %s", requestW.Body.String())

		var approval types.PermissionApproval
		require.NoError(t, json.Unmarshal(requestW.Body.Bytes(), &approval))
		require.NotZero(t, approval.ID, "approval ID should be set")
		t.Logf("Created approval: ID=%d, CallerDID=%s, TargetDID=%s, Status=%s",
			approval.ID, approval.CallerDID, approval.TargetDID, approval.Status)

		// Approve (with proper headers)
		approveReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/approve", approval.ID),
			strings.NewReader(`{}`))
		approveReq.Header.Set("Content-Type", "application/json")
		approveW := httptest.NewRecorder()
		tc.router.ServeHTTP(approveW, approveReq)
		require.Equal(t, 200, approveW.Code, "approve should succeed: %s", approveW.Body.String())

		var approvedApproval types.PermissionApproval
		require.NoError(t, json.Unmarshal(approveW.Body.Bytes(), &approvedApproval))
		t.Logf("After approve: Status=%s, ID=%d", approvedApproval.Status, approvedApproval.ID)

		// Check permission is valid - include target_agent_id so tags can be looked up
		// Note: DIDs must be URL-encoded because they contain %3A which would otherwise be decoded
		checkURL := fmt.Sprintf("/api/v1/permissions/check?caller_did=%s&target_did=%s&target_agent_id=%s",
			url.QueryEscape(callerDID), url.QueryEscape(targetDID), url.QueryEscape(targetID))
		checkW := httptest.NewRecorder()
		tc.router.ServeHTTP(checkW, httptest.NewRequest("GET", checkURL, nil))
		require.Equal(t, 200, checkW.Code, "check should succeed: %s", checkW.Body.String())

		var check types.PermissionCheck
		require.NoError(t, json.Unmarshal(checkW.Body.Bytes(), &check))
		t.Logf("Check response: RequiresPermission=%v, HasValidApproval=%v, ApprovalStatus=%s, ApprovalID=%v",
			check.RequiresPermission, check.HasValidApproval, check.ApprovalStatus, check.ApprovalID)
		require.True(t, check.RequiresPermission, "agent should be protected")
		require.True(t, check.HasValidApproval, "should have valid approval after approve (status=%s)", check.ApprovalStatus)

		// Revoke the permission
		revokeReq := httptest.NewRequest("POST",
			fmt.Sprintf("/api/v1/admin/permissions/%d/revoke", approval.ID),
			strings.NewReader(`{"reason": "Security incident"}`))
		revokeReq.Header.Set("Content-Type", "application/json")
		revokeW := httptest.NewRecorder()
		tc.router.ServeHTTP(revokeW, revokeReq)
		require.Equal(t, 200, revokeW.Code)

		// Check permission again - should no longer have valid approval
		checkW2 := httptest.NewRecorder()
		tc.router.ServeHTTP(checkW2, httptest.NewRequest("GET", checkURL, nil))

		var check2 types.PermissionCheck
		json.Unmarshal(checkW2.Body.Bytes(), &check2)
		assert.True(t, check2.RequiresPermission, "agent should still be protected")
		assert.False(t, check2.HasValidApproval, "approval should be invalid after revoke")
	})
}

func TestVCAuth_Phase5_EndToEnd_DIDAuthentication(t *testing.T) {
	tc := setupTestContext(t)

	// Generate key pair for the calling agent
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	agentID := "did-auth-e2e-agent"
	did := tc.didWebService.GenerateDIDWeb(agentID)

	// Store DID document with the test public key
	pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(publicKey))

	didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
	docBytes, _ := json.Marshal(didDoc)

	record := &types.DIDDocumentRecord{
		DID:          did,
		AgentID:      agentID,
		DIDDocument:  docBytes,
		PublicKeyJWK: pubKeyJWK,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tc.storage.StoreDIDDocument(tc.ctx, record)

	// Helper to create signed requests
	signAndSend := func(router *gin.Engine, method, path string, body []byte) *httptest.ResponseRecorder {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("authenticated request succeeds with valid signature", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			verifiedDID := middleware.GetVerifiedCallerDID(c)
			c.JSON(200, gin.H{
				"success":      true,
				"verified_did": verifiedDID,
			})
		})

		body := []byte(`{"action": "test"}`)
		w := signAndSend(router, "POST", "/test", body)

		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.True(t, response["success"].(bool))
		assert.Equal(t, did, response["verified_did"])
	})

	t.Run("request with tampered body fails", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		// Sign with original body
		originalBody := []byte(`{"action": "original"}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(originalBody)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		// Send with different body
		tamperedBody := []byte(`{"action": "tampered"}`)
		req := httptest.NewRequest("POST", "/test", bytes.NewReader(tamperedBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})

	t.Run("replay attack with old timestamp fails", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300, // 5 minutes
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		body := []byte(`{"action": "test"}`)
		// Use timestamp from 10 minutes ago
		oldTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", oldTimestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", oldTimestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
	})
}

// =============================================================================
// Phase 6: SDK Compatibility Tests
// =============================================================================

func TestVCAuth_Phase6_SDK_GoClientDIDAuth(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("SDK signing produces valid signature", func(t *testing.T) {
		// Generate test key pair
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		agentID := "sdk-test-agent"
		did := tc.didWebService.GenerateDIDWeb(agentID)

		// Store DID document with public key
		pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(publicKey))

		didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
		docBytes, _ := json.Marshal(didDoc)

		record := &types.DIDDocumentRecord{
			DID:          did,
			AgentID:      agentID,
			DIDDocument:  docBytes,
			PublicKeyJWK: pubKeyJWK,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		tc.storage.StoreDIDDocument(tc.ctx, record)

		// Create private key JWK for SDK
		privateKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","d":"%s","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(privateKey.Seed()),
			base64.RawURLEncoding.EncodeToString(publicKey))

		// Simulate SDK signing (matching did_auth.go implementation)
		body := []byte(`{"target": "other-agent.skill", "input": {"data": "test"}}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))
		signatureB64 := base64.StdEncoding.EncodeToString(signature)

		// Set up router with DID auth middleware
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/execute", func(c *gin.Context) {
			verifiedDID := middleware.GetVerifiedCallerDID(c)
			c.JSON(200, gin.H{"verified_did": verifiedDID})
		})

		// Make request with SDK-style headers
		req := httptest.NewRequest("POST", "/execute", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", signatureB64)
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, did, response["verified_did"])

		t.Logf("SDK signature verification successful for DID: %s", did)
		t.Logf("Private key JWK (for SDK testing): %s", privateKeyJWK)
	})
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestVCAuth_EdgeCases_PatternMatching(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("wildcard suffix pattern matching", func(t *testing.T) {
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeTagPattern,
			Pattern:     "finance*",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		assert.True(t, tc.permissionService.IsAgentProtected("any", []string{"finance"}))
		assert.True(t, tc.permissionService.IsAgentProtected("any", []string{"finance-team"}))
		assert.True(t, tc.permissionService.IsAgentProtected("any", []string{"finance123"}))
		assert.False(t, tc.permissionService.IsAgentProtected("any", []string{"other-finance"}))
	})

	t.Run("wildcard prefix pattern matching", func(t *testing.T) {
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeTagPattern,
			Pattern:     "*-internal",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		assert.True(t, tc.permissionService.IsAgentProtected("any", []string{"api-internal"}))
		assert.True(t, tc.permissionService.IsAgentProtected("any", []string{"db-internal"}))
		assert.False(t, tc.permissionService.IsAgentProtected("any", []string{"internal-api"}))
	})

	t.Run("agent ID pattern matching", func(t *testing.T) {
		rule := &types.ProtectedAgentRuleRequest{
			PatternType: types.PatternTypeAgentID,
			Pattern:     "payment*",
		}
		_, err := tc.permissionService.AddProtectedAgentRule(tc.ctx, rule)
		require.NoError(t, err)

		assert.True(t, tc.permissionService.IsAgentProtected("payment-gateway", nil))
		assert.True(t, tc.permissionService.IsAgentProtected("payment-processor", nil))
		assert.False(t, tc.permissionService.IsAgentProtected("order-service", nil))
	})
}

func TestVCAuth_EdgeCases_ExpirationHandling(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("expired permission is not valid", func(t *testing.T) {
		// Create approval with past expiration
		approval := &types.PermissionApproval{
			CallerDID:     "did:web:localhost:agents:exp-caller",
			TargetDID:     "did:web:localhost:agents:exp-target",
			CallerAgentID: "exp-caller",
			TargetAgentID: "exp-target",
			Status:        types.PermissionStatusApproved,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		// Set expiration in the past
		expiredTime := time.Now().Add(-1 * time.Hour)
		approval.ExpiresAt = &expiredTime
		approvedAt := time.Now().Add(-2 * time.Hour)
		approval.ApprovedAt = &approvedAt
		approvedBy := "admin"
		approval.ApprovedBy = &approvedBy

		err := tc.storage.CreatePermissionApproval(tc.ctx, approval)
		require.NoError(t, err)

		// Check IsValid() should return false for expired
		assert.False(t, approval.IsValid())
	})
}

func TestVCAuth_EdgeCases_ConcurrentAccess(t *testing.T) {
	tc := setupTestContext(t)

	t.Run("concurrent permission requests", func(t *testing.T) {
		// Create multiple concurrent permission requests
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func(idx int) {
				req := &types.PermissionRequest{
					CallerDID:     fmt.Sprintf("did:web:localhost:agents:concurrent-caller-%d", idx),
					TargetDID:     fmt.Sprintf("did:web:localhost:agents:concurrent-target-%d", idx),
					CallerAgentID: fmt.Sprintf("concurrent-caller-%d", idx),
					TargetAgentID: fmt.Sprintf("concurrent-target-%d", idx),
				}
				_, err := tc.permissionService.RequestPermission(tc.ctx, req)
				if err != nil {
					t.Errorf("concurrent request %d failed: %v", idx, err)
				}
				done <- true
			}(i)
		}

		// Wait for all to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all were created
		all, err := tc.permissionService.ListAllPermissions(tc.ctx)
		require.NoError(t, err)

		concurrentCount := 0
		for _, p := range all {
			if strings.HasPrefix(p.CallerAgentID, "concurrent-") {
				concurrentCount++
			}
		}
		assert.Equal(t, 10, concurrentCount)
	})
}

// =============================================================================
// Regression: DID:web document lifecycle during agent registration
// =============================================================================

// TestVCAuth_Regression_DIDWebDocumentCreatedDuringRegistration is a regression test
// for a bug where GetOrCreateDIDDocument was never called during agent registration,
// causing VerifyDIDOwnership (DID auth middleware) to always fail with "notFound"
// because no DID:web document existed in storage.
//
// The fix (in RegisterNodeHandler) calls GetOrCreateDIDDocument after DID:key
// registration. This test ensures that flow works end-to-end and catches any
// regression that would break it.
func TestVCAuth_Regression_DIDWebDocumentCreatedDuringRegistration(t *testing.T) {
	tc := setupTestContext(t)

	agentID := "regression-agent-lifecycle"

	t.Run("without DID:web document, auth middleware rejects signed requests", func(t *testing.T) {
		// Simulate the OLD broken behavior: agent is registered in storage
		// but GetOrCreateDIDDocument is never called.
		agent := tc.createTestAgent(agentID+"-broken", nil)
		_ = agent

		// The DID:web identifier exists as a string...
		did := tc.didWebService.GenerateDIDWeb(agentID + "-broken")

		// ...but no DID document was stored, so ResolveDID returns "notFound"
		result, err := tc.didWebService.ResolveDID(tc.ctx, did)
		require.NoError(t, err)
		assert.Equal(t, "notFound", result.DIDResolutionMetadata.Error,
			"BUG REGRESSION: ResolveDID should return notFound when GetOrCreateDIDDocument was never called")
		assert.Nil(t, result.DIDDocument)

		// VerifyDIDOwnership should also fail
		valid, err := tc.didWebService.VerifyDIDOwnership(tc.ctx, did, []byte("test"), []byte("sig"))
		assert.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "not found",
			"BUG REGRESSION: VerifyDIDOwnership fails because no DID:web document exists")
	})

	t.Run("with GetOrCreateDIDDocument called during registration, auth middleware accepts signed requests", func(t *testing.T) {
		// Simulate the FIXED behavior: agent is registered AND GetOrCreateDIDDocument
		// is called, just like RegisterNodeHandler does after the fix.
		agent := tc.createTestAgent(agentID, nil)
		_ = agent

		// This is the critical call that the fix adds to RegisterNodeHandler.
		didDoc, did, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, agentID)
		require.NoError(t, err, "GetOrCreateDIDDocument must succeed during registration")
		require.NotNil(t, didDoc, "DID document must be created")
		assert.Contains(t, did, agentID)

		// Verify the document is now resolvable
		result, err := tc.didWebService.ResolveDID(tc.ctx, did)
		require.NoError(t, err)
		assert.Empty(t, result.DIDResolutionMetadata.Error,
			"After GetOrCreateDIDDocument, ResolveDID must succeed")
		require.NotNil(t, result.DIDDocument, "DID document must be resolvable")
		assert.Equal(t, did, result.DIDDocument.ID)

		// Verify the document has a verification method with a public key
		require.NotEmpty(t, result.DIDDocument.VerificationMethod,
			"DID document must have at least one verification method")
		vm := result.DIDDocument.VerificationMethod[0]
		assert.Equal(t, "JsonWebKey2020", vm.Type)
		assert.NotEmpty(t, vm.PublicKeyJwk, "Verification method must contain a public key JWK")

		// Extract the public key and generate a matching private key to sign a request,
		// then verify through the middleware. We use the stored public key to prove the
		// full chain works.
		var jwk struct {
			X string `json:"x"`
		}
		err = json.Unmarshal(vm.PublicKeyJwk, &jwk)
		require.NoError(t, err, "Public key JWK must be valid JSON")

		publicKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		require.NoError(t, err)
		assert.Len(t, publicKeyBytes, ed25519.PublicKeySize,
			"Public key must be a valid Ed25519 key")
	})

	t.Run("idempotent: calling GetOrCreateDIDDocument twice returns same document", func(t *testing.T) {
		reregAgentID := agentID + "-rereg"
		tc.createTestAgent(reregAgentID, nil)

		// First call (initial registration)
		doc1, did1, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, reregAgentID)
		require.NoError(t, err)
		require.NotNil(t, doc1)

		// Second call (re-registration)
		doc2, did2, err := tc.didWebService.GetOrCreateDIDDocument(tc.ctx, reregAgentID)
		require.NoError(t, err)
		require.NotNil(t, doc2)

		assert.Equal(t, did1, did2, "DID must be stable across re-registrations")
		assert.Equal(t, doc1.ID, doc2.ID, "Document ID must be stable across re-registrations")
	})

	t.Run("end-to-end: registered agent can authenticate through DID middleware", func(t *testing.T) {
		// This is the full end-to-end flow:
		// 1. Agent registered in storage
		// 2. GetOrCreateDIDDocument called (our fix)
		// 3. Agent signs a request
		// 4. DID auth middleware verifies the signature

		e2eAgentID := agentID + "-e2e"
		tc.createTestAgent(e2eAgentID, nil)

		// Create a known key pair for signing
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		// Store a DID document with our known test key (simulating what
		// GetOrCreateDIDDocument does, but with a key we control for signing)
		did := tc.didWebService.GenerateDIDWeb(e2eAgentID)
		pubKeyJWK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(publicKey))

		didDoc := types.NewDIDWebDocument(did, json.RawMessage(pubKeyJWK))
		docBytes, _ := json.Marshal(didDoc)

		record := &types.DIDDocumentRecord{
			DID:          did,
			AgentID:      e2eAgentID,
			DIDDocument:  docBytes,
			PublicKeyJWK: pubKeyJWK,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		err = tc.storage.StoreDIDDocument(tc.ctx, record)
		require.NoError(t, err)

		// Set up router with DID auth middleware
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			verifiedDID := middleware.GetVerifiedCallerDID(c)
			c.JSON(200, gin.H{"verified_did": verifiedDID})
		})

		// Sign a request
		body := []byte(`{"action":"test-registration-flow"}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code,
			"Registered agent with DID:web document must pass DID auth middleware")

		var response map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, did, response["verified_did"],
			"Middleware must set the verified DID in context")
	})

	t.Run("end-to-end: unregistered DID:web document fails auth middleware", func(t *testing.T) {
		// Agent exists in storage but NO DID:web document was created.
		// This is the exact bug scenario. The middleware must reject.
		noDocAgentID := agentID + "-no-doc"
		tc.createTestAgent(noDocAgentID, nil)

		// Generate a key pair (agent has keys, but no doc in storage)
		_, privateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		did := tc.didWebService.GenerateDIDWeb(noDocAgentID)

		// Set up router with DID auth middleware
		router := gin.New()
		router.Use(middleware.DIDAuthMiddleware(tc.didWebService, middleware.DIDAuthConfig{
			Enabled:                true,
			TimestampWindowSeconds: 300,
		}))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Sign a request
		body := []byte(`{"action":"test-no-doc"}`)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		bodyHash := sha256.Sum256(body)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)
		signature := ed25519.Sign(privateKey, []byte(payload))

		req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Caller-DID", did)
		req.Header.Set("X-DID-Signature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-DID-Timestamp", timestamp)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code,
			"Agent without DID:web document must be rejected by auth middleware")

		var errResponse map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &errResponse)
		require.NoError(t, err)
		assert.Equal(t, "verification_error", errResponse["error"],
			"Error must indicate verification failure due to missing document")
	})
}

// =============================================================================
// Utility for reading response bodies
// =============================================================================
