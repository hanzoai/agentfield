# VC-Based Authorization System - Complete Implementation Guide

**Version:** 1.1
**Created:** February 4, 2026
**Updated:** February 5, 2026
**Branch:** `feat/vc-authorization`
**Status:** Implementation Complete (Ready for Testing)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Architecture Decisions](#architecture-decisions)
5. [Implementation Status](#implementation-status)
6. [Phase 1: Foundation (COMPLETED)](#phase-1-foundation-completed)
7. [Phase 2: DID Authentication (COMPLETED)](#phase-2-did-authentication-completed)
8. [Phase 3: Storage Implementation (COMPLETED)](#phase-3-storage-implementation-completed)
9. [Phase 4: API Endpoints (COMPLETED)](#phase-4-api-endpoints-completed)
10. [Phase 5: Execute Handler Integration (COMPLETED)](#phase-5-execute-handler-integration-completed)
11. [Phase 6: Configuration (COMPLETED)](#phase-6-configuration-completed)
12. [Phase 7: Admin UI (COMPLETED)](#phase-7-admin-ui-completed)
13. [Phase 8: SDK Updates (COMPLETED)](#phase-8-sdk-updates-completed)
14. [Testing Strategy](#testing-strategy)
15. [Migration & Rollout](#migration--rollout)
16. [File Reference](#file-reference)

---

## Executive Summary

This document provides a complete implementation guide for the VC-based authorization system in AgentField. The system controls which agents can call which other agents, with admin approval required for protected agents.

**Key Features:**
- Cryptographic identity verification via `did:web`
- Permission approval workflow (request → admin approval → access granted)
- Real-time revocation capability
- Proactive dependency declaration at registration
- Audit trail via Verifiable Credentials

---

## Problem Statement

### Current State
- Agents can call any other agent without restriction
- No cryptographic verification of caller identity
- `X-Caller-DID` header is trusted without verification (security vulnerability)
- No admin oversight of inter-agent communication

### Desired State
- Protected agents require explicit permission to call
- Caller identity cryptographically verified via DID signatures
- Admin approval workflow for permission requests
- Ability to revoke permissions in real-time
- Complete audit trail

---

## Solution Overview

### End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE AUTHORIZATION FLOW                              │
└─────────────────────────────────────────────────────────────────────────────────┘

REGISTRATION PHASE:
┌─────────┐                    ┌──────────────┐                    ┌───────┐
│ Agent A │                    │ Control Plane│                    │ Admin │
└────┬────┘                    └──────┬───────┘                    └───┬───┘
     │                                │                                │
     │  1. Register                   │                                │
     │  {agent_id, tags}              │                                │
     │  ──────────────────────────►   │                                │
     │                                │                                │
     │                                │  2. Generate did:web           │
     │                                │  3. Generate key pair          │
     │                                │  4. Store DID document         │
     │                                │                                │
     │  5. Response:                  │                                │
     │  {did, public_key_jwk,         │                                │
     │   private_key_jwk}             │                                │
     │  ◄──────────────────────────   │                                │
     │                                │                                │
     │  8. Use locally generated      │                                │
     │     private key for signing    │                                │
     │                                │                                │
     │                                │  9. Show in Admin UI           │
     │                                │  ─────────────────────────────►│
     │                                │                                │
     │                                │                    10. Approve │
     │                                │  ◄─────────────────────────────│
     │                                │                                │
     │                                │  11. Store approval            │

CALL PHASE:
     │                                │                                │
     │  12. Build request to Agent B  │                                │
     │      Sign with private key     │                                │
     │                                │                                │
     │  13. POST /execute             │                                │
     │  Headers:                      │                                │
     │    X-Caller-DID: did:web:...   │                                │
     │    X-DID-Signature: base64(sig)│                                │
     │    X-DID-Timestamp: 1707091200 │                                │
     │  ──────────────────────────►   │                                │
     │                                │                                │
     │                                │  14. Resolve DID → public key  │
     │                                │  15. Verify signature          │
     │                                │  16. Check timestamp           │
     │                                │  17. Is target protected?      │
     │                                │  18. Has caller approval?      │
     │                                │  19. Forward to Agent B        │
     │                                │                                │
     │  20. Response from Agent B     │                                │
     │  ◄──────────────────────────   │                                │
```

### Key Components

| Component | Purpose | Status |
|-----------|---------|--------|
| DID Web Service | Generate/resolve did:web identifiers | ✅ Done |
| Permission Service | Manage approvals, check permissions | ✅ Done |
| DID Auth Middleware | Verify caller signatures | ✅ Done |
| Storage Layer | Persist DIDs, approvals, rules | ✅ Done |
| Permission API | HTTP endpoints for permissions | ✅ Done |
| Execute Integration | Check permissions on calls | ✅ Done |
| Admin UI | Approve/reject/revoke permissions | ✅ Done |
| SDK Updates | Sign requests with private key | ✅ Done |

---

## Architecture Decisions

### Decision 1: did:web over did:key

**Context:** Need ability to revoke DIDs in real-time.

**Decision:** Use `did:web` method instead of `did:key`.

**Rationale:**
- `did:key` embeds public key in identifier - cannot be revoked
- `did:web` resolves to URL - control plane can return 404/revoked
- Format: `did:web:{domain}:agents:{agentID}`

**Implementation:** See `DIDWebService` in [did_web_service.go](../control-plane/internal/services/did_web_service.go)

### Decision 2: Control Plane as Key Authority

**Context:** Who generates and manages cryptographic keys?

**Decision:** Control plane generates keys, delivers private key once at registration.

**Rationale:**
- Deterministic key derivation from master seed
- Can regenerate if needed (recovery scenario)
- Simpler agent implementation
- Trade-off: private key transmitted once over HTTPS

**Alternative Considered:** Agent generates own keys, sends public key to control plane.

### Decision 3: Signature-Based DID Authentication

**Context:** How to verify caller actually owns claimed DID?

**Decision:** Require cryptographic signature on every request.

**Signature Payload Format:**
```
payload = "{timestamp}:{sha256(request_body)}"
signature = Ed25519.sign(payload, private_key)
```

**Headers:**
```
X-Caller-DID: did:web:example.com:agents:agent-a
X-DID-Signature: base64(signature)
X-DID-Timestamp: 1707091200
```

**Verification:**
1. Parse claimed DID from header
2. Resolve DID document → get public key
3. Reconstruct payload from timestamp + body hash
4. Verify signature with Ed25519
5. Check timestamp within 5-minute window

### Decision 4: Permission Granularity

**Context:** How to define what needs permission?

**Decision:** Permission required for protected agents (defined by patterns).
Canonical tag matching uses plain tag values (for example `admin`), not `key:value` strings.

**Protection Rules (config file):**
```yaml
features:
  did:
    authorization:
      protected_agents:
        - pattern_type: tag           # Exact plain-tag match
          pattern: admin
        - pattern_type: tag_pattern   # Wildcard plain-tag match
          pattern: "finance*"
        - pattern_type: agent_id      # Specific agent
          pattern: "payment-gateway"
```

**Permission Check:** `(caller_did, target_did)` pair must have approved status.

### Permission VC Signing Status

`GET /api/v1/permissions/:id/vc` currently returns an unsigned audit record (`proof.type = "UnsignedAuditRecord"`).  
Treat it as non-verifiable until cryptographic signing is implemented.

### Decision 5: Proactive Dependency Declaration

**Context:** When should permission requests be created?

**Decision:** At call time: If no permission exists and `auto_request_on_deny` is enabled, auto-create pending request.

> **Note:** Proactive dependency declaration at registration time (`dependencies: ["admin"]`) was considered but is not yet implemented. Currently, permissions are only requested when a call is denied.

### Decision 6: Agent Tags are Informational Only

**Context:** Do caller's own tags affect authorization?

**Decision:** No. Tags are identity declaration, not permissions.

**Rationale:**
- Simpler mental model
- Tags help admin decide, but system doesn't auto-enforce
- Prevents complexity of tag-based auto-approve policies
- Can add auto-approve rules later if needed

---

## Implementation Status

### Completed ✅

| Item | Files | Notes |
|------|-------|-------|
| Branch created | `feat/vc-authorization` | From latest `main` |
| Architecture doc | `docs/VC_AUTHORIZATION_ARCHITECTURE.md` | v1.1 with flows |
| Security doc | `docs/DID_AUTHENTICATION_SECURITY.md` | Signature verification |
| DB migration: permission_approvals | `migrations/018_create_permission_approvals.sql` | Stores approvals |
| DB migration: did_documents | `migrations/019_create_did_documents.sql` | Stores DID docs |
| DB migration: protected_agents | `migrations/020_create_protected_agents.sql` | Protection rules |
| Permission types | `pkg/types/permission_types.go` | All permission structs |
| DID Web types | `pkg/types/did_web_types.go` | DID document structs |
| DID Web Service | `internal/services/did_web_service.go` | Generate/resolve DIDs |
| Permission Service | `internal/services/permission_service.go` | Core permission logic |

### Recently Completed ✅

| Item | Files | Notes |
|------|-------|-------|
| DID Auth Middleware | `internal/server/middleware/did_auth.go` | Signature verification |
| Permission Check Middleware | `internal/server/middleware/permission.go` | Protected agent checks |
| Storage implementation | `internal/storage/local.go`, `models.go` | SQLite implementation |
| Permission API endpoints | `internal/handlers/permissions.go` | REST API handlers |
| Admin API endpoints | `internal/handlers/admin/permissions.go` | Admin management |
| Execute handler integration | Via middleware | Middleware pattern |
| Configuration loading | `internal/config/config.go` | Protected agents config |
| Admin UI - Pending Permissions | `web/client/src/pages/PendingPermissionsPage.tsx` | Approve/reject UI |
| Admin UI - Permission History | `web/client/src/pages/PermissionHistoryPage.tsx` | Audit trail |
| Admin UI - Protected Agents | `web/client/src/pages/ProtectedAgentsPage.tsx` | Rule management |
| Python SDK DID Auth | `sdk/python/agentfield/did_auth.py` | Ed25519 signing |
| Go SDK DID Auth | `sdk/go/client/did_auth.go` | Ed25519 signing |

### Remaining Tasks 📋

| Item | Priority | Notes |
|------|----------|-------|
| Integration testing | P0 | End-to-end permission flow |
| PostgreSQL storage implementation | P1 | For cloud deployments |
| Documentation updates | P2 | User-facing docs |

---

## Phase 1: Foundation (COMPLETED)

### 1.1 Database Migrations

**Files Created:**
- `control-plane/migrations/018_create_permission_approvals.sql`
- `control-plane/migrations/019_create_did_documents.sql`
- `control-plane/migrations/020_create_protected_agents.sql`

**permission_approvals table:**
```sql
CREATE TABLE IF NOT EXISTS permission_approvals (
    id              BIGSERIAL PRIMARY KEY,
    caller_did      TEXT NOT NULL,
    target_did      TEXT NOT NULL,
    caller_agent_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    approved_by     TEXT,
    approved_at     TIMESTAMP WITH TIME ZONE,
    rejected_by     TEXT,
    rejected_at     TIMESTAMP WITH TIME ZONE,
    revoked_by      TEXT,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    expires_at      TIMESTAMP WITH TIME ZONE,
    reason          TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_caller_target UNIQUE (caller_did, target_did)
);
```

**did_documents table:**
```sql
CREATE TABLE IF NOT EXISTS did_documents (
    did             TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL UNIQUE,
    did_document    JSONB NOT NULL,
    public_key_jwk  TEXT NOT NULL,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

**protected_agents_config table:**
```sql
CREATE TABLE IF NOT EXISTS protected_agents_config (
    id              BIGSERIAL PRIMARY KEY,
    pattern_type    TEXT NOT NULL,            -- 'tag', 'tag_pattern', 'agent_id'
    pattern         TEXT NOT NULL,
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_pattern UNIQUE (pattern_type, pattern)
);
```

### 1.2 Type Definitions

**File:** `control-plane/pkg/types/permission_types.go`

Key types:
```go
// Permission statuses
type PermissionStatus string
const (
    PermissionStatusPending  PermissionStatus = "pending"
    PermissionStatusApproved PermissionStatus = "approved"
    PermissionStatusRejected PermissionStatus = "rejected"
    PermissionStatusRevoked  PermissionStatus = "revoked"
    PermissionStatusExpired  PermissionStatus = "expired"
)

// Permission approval record
type PermissionApproval struct {
    ID            int64            `json:"id" db:"id"`
    CallerDID     string           `json:"caller_did" db:"caller_did"`
    TargetDID     string           `json:"target_did" db:"target_did"`
    CallerAgentID string           `json:"caller_agent_id" db:"caller_agent_id"`
    TargetAgentID string           `json:"target_agent_id" db:"target_agent_id"`
    Status        PermissionStatus `json:"status" db:"status"`
    ApprovedBy    *string          `json:"approved_by,omitempty" db:"approved_by"`
    ApprovedAt    *time.Time       `json:"approved_at,omitempty" db:"approved_at"`
    RejectedBy    *string          `json:"rejected_by,omitempty" db:"rejected_by"`
    RejectedAt    *time.Time       `json:"rejected_at,omitempty" db:"rejected_at"`
    RevokedBy     *string          `json:"revoked_by,omitempty" db:"revoked_by"`
    RevokedAt     *time.Time       `json:"revoked_at,omitempty" db:"revoked_at"`
    ExpiresAt     *time.Time       `json:"expires_at,omitempty" db:"expires_at"`
    Reason        *string          `json:"reason,omitempty" db:"reason"`
    CreatedAt     time.Time        `json:"created_at" db:"created_at"`
    UpdatedAt     time.Time        `json:"updated_at" db:"updated_at"`
}

// Permission check result
type PermissionCheck struct {
    RequiresPermission bool             `json:"requires_permission"`
    HasValidApproval   bool             `json:"has_valid_approval"`
    ApprovalStatus     PermissionStatus `json:"approval_status,omitempty"`
    ApprovalID         *int64           `json:"approval_id,omitempty"`
    ExpiresAt          *time.Time       `json:"expires_at,omitempty"`
    VC                 string           `json:"vc,omitempty"`
}

// Protected agent rule
type ProtectedAgentRule struct {
    ID          int64                     `json:"id" db:"id"`
    PatternType ProtectedAgentPatternType `json:"pattern_type" db:"pattern_type"`
    Pattern     string                    `json:"pattern" db:"pattern"`
    Description *string                   `json:"description,omitempty" db:"description"`
    Enabled     bool                      `json:"enabled" db:"enabled"`
    CreatedAt   time.Time                 `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time                 `json:"updated_at" db:"updated_at"`
}

// Pattern types for protection rules
type ProtectedAgentPatternType string
const (
    PatternTypeTag        ProtectedAgentPatternType = "tag"
    PatternTypeTagPattern ProtectedAgentPatternType = "tag_pattern"
    PatternTypeAgentID    ProtectedAgentPatternType = "agent_id"
)
```

**File:** `control-plane/pkg/types/did_web_types.go`

Key types:
```go
// DID Web Document (W3C standard)
type DIDWebDocument struct {
    Context            []string             `json:"@context"`
    ID                 string               `json:"id"`
    Controller         string               `json:"controller,omitempty"`
    VerificationMethod []VerificationMethod `json:"verificationMethod"`
    Authentication     []string             `json:"authentication"`
    AssertionMethod    []string             `json:"assertionMethod,omitempty"`
    KeyAgreement       []string             `json:"keyAgreement,omitempty"`
    Service            []DIDService         `json:"service,omitempty"`
}

// Verification method in DID Document
type VerificationMethod struct {
    ID           string          `json:"id"`
    Type         string          `json:"type"`
    Controller   string          `json:"controller"`
    PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
}

// DID Document database record
type DIDDocumentRecord struct {
    DID          string          `json:"did" db:"did"`
    AgentID      string          `json:"agent_id" db:"agent_id"`
    DIDDocument  json.RawMessage `json:"did_document" db:"did_document"`
    PublicKeyJWK string          `json:"public_key_jwk" db:"public_key_jwk"`
    RevokedAt    *time.Time      `json:"revoked_at,omitempty" db:"revoked_at"`
    CreatedAt    time.Time       `json:"created_at" db:"created_at"`
    UpdatedAt    time.Time       `json:"updated_at" db:"updated_at"`
}

// DID Resolution result
type DIDResolutionResult struct {
    DIDDocument           *DIDWebDocument       `json:"didDocument,omitempty"`
    DIDResolutionMetadata DIDResolutionMetadata `json:"didResolutionMetadata"`
    DIDDocumentMetadata   DIDDocumentMetadata   `json:"didDocumentMetadata"`
}
```

### 1.3 DID Web Service

**File:** `control-plane/internal/services/did_web_service.go`

**Key Methods:**

```go
// Generate did:web identifier
func (s *DIDWebService) GenerateDIDWeb(agentID string) string {
    encodedDomain := strings.ReplaceAll(s.domain, ":", "%3A")
    return fmt.Sprintf("did:web:%s:agents:%s", encodedDomain, agentID)
}

// Create and store DID document
func (s *DIDWebService) CreateDIDDocument(ctx context.Context, agentID string, publicKeyJWK json.RawMessage) (*types.DIDWebDocument, error)

// Resolve DID to document
func (s *DIDWebService) ResolveDID(ctx context.Context, did string) (*types.DIDResolutionResult, error)

// Get or create DID document for agent
func (s *DIDWebService) GetOrCreateDIDDocument(ctx context.Context, agentID string) (*types.DIDWebDocument, string, error)

// Revoke a DID
func (s *DIDWebService) RevokeDID(ctx context.Context, did string) error

// Verify signature against DID document's public key
func (s *DIDWebService) VerifyDIDOwnership(ctx context.Context, did string, message []byte, signature []byte) (bool, error)

// Get private key for agent (for signing VCs)
func (s *DIDWebService) GetPrivateKeyJWK(agentID string) (string, error)
```

**Storage Interface Required:**
```go
type DIDWebStorage interface {
    StoreDIDDocument(ctx context.Context, record *types.DIDDocumentRecord) error
    GetDIDDocument(ctx context.Context, did string) (*types.DIDDocumentRecord, error)
    GetDIDDocumentByAgentID(ctx context.Context, agentID string) (*types.DIDDocumentRecord, error)
    RevokeDIDDocument(ctx context.Context, did string) error
    ListDIDDocuments(ctx context.Context) ([]*types.DIDDocumentRecord, error)
}
```

### 1.4 Permission Service

**File:** `control-plane/internal/services/permission_service.go`

**Key Methods:**

```go
// Initialize - load protected agent rules from storage
func (s *PermissionService) Initialize(ctx context.Context) error

// Check if permission system is enabled
func (s *PermissionService) IsEnabled() bool

// Check if an agent is protected
func (s *PermissionService) IsAgentProtected(agentID string, tags []string) bool

// Check if caller has permission to call target
func (s *PermissionService) CheckPermission(ctx context.Context, callerDID, targetDID string, targetAgentID string, targetTags []string) (*types.PermissionCheck, error)

// Request permission to call a target
func (s *PermissionService) RequestPermission(ctx context.Context, req *types.PermissionRequest) (*types.PermissionApproval, error)

// Approve a pending permission request
func (s *PermissionService) ApprovePermission(ctx context.Context, id int64, approvedBy string, durationHours *int) (*types.PermissionApproval, error)

// Reject a pending permission request
func (s *PermissionService) RejectPermission(ctx context.Context, id int64, rejectedBy string, reason string) (*types.PermissionApproval, error)

// Revoke an approved permission
func (s *PermissionService) RevokePermission(ctx context.Context, id int64, revokedBy string, reason string) (*types.PermissionApproval, error)

// List pending permission requests
func (s *PermissionService) ListPendingPermissions(ctx context.Context) ([]*types.PermissionApproval, error)

// List all permissions
func (s *PermissionService) ListAllPermissions(ctx context.Context) ([]*types.PermissionApproval, error)

// Generate PermissionVC for approved permission
func (s *PermissionService) GeneratePermissionVC(ctx context.Context, approval *types.PermissionApproval) (*types.PermissionVCDocument, error)

// Add protected agent rule
func (s *PermissionService) AddProtectedAgentRule(ctx context.Context, req *types.ProtectedAgentRuleRequest) (*types.ProtectedAgentRule, error)

// Remove protected agent rule
func (s *PermissionService) RemoveProtectedAgentRule(ctx context.Context, id int64) error
```

**Storage Interface Required:**
```go
type PermissionStorage interface {
    // Permission approvals
    CreatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
    GetPermissionApproval(ctx context.Context, callerDID, targetDID string) (*types.PermissionApproval, error)
    GetPermissionApprovalByID(ctx context.Context, id int64) (*types.PermissionApproval, error)
    UpdatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
    ListPermissionApprovals(ctx context.Context, status types.PermissionStatus) ([]*types.PermissionApproval, error)
    ListAllPermissionApprovals(ctx context.Context) ([]*types.PermissionApproval, error)

    // Protected agent rules
    GetProtectedAgentRules(ctx context.Context) ([]*types.ProtectedAgentRule, error)
    CreateProtectedAgentRule(ctx context.Context, rule *types.ProtectedAgentRule) error
    DeleteProtectedAgentRule(ctx context.Context, id int64) error
}
```

**Pattern Matching Logic:**
```go
func matchesPattern(pattern, value string) bool {
    // Exact match
    if pattern == value {
        return true
    }
    // Full wildcard
    if pattern == "*" {
        return true
    }
    // Prefix wildcard (e.g., "finance*")
    if strings.HasSuffix(pattern, "*") {
        prefix := strings.TrimSuffix(pattern, "*")
        return strings.HasPrefix(value, prefix)
    }
    // Suffix wildcard (e.g., "*-internal")
    if strings.HasPrefix(pattern, "*") {
        suffix := strings.TrimPrefix(pattern, "*")
        return strings.HasSuffix(value, suffix)
    }
    return false
}
```

---

## Phase 2: DID Authentication (COMPLETED)

### 2.1 Create DID Auth Middleware

**File to Create:** `control-plane/internal/middleware/did_auth.go`

```go
package middleware

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "time"

    "github.com/Agent-Field/agentfield/control-plane/internal/logger"
    "github.com/Agent-Field/agentfield/control-plane/internal/services"
    "github.com/gin-gonic/gin"
)

const (
    // Headers
    HeaderCallerDID     = "X-Caller-DID"
    HeaderDIDSignature  = "X-DID-Signature"
    HeaderDIDTimestamp  = "X-DID-Timestamp"

    // Context keys
    ContextVerifiedDID  = "verified_caller_did"
    ContextDIDVerified  = "did_verified"

    // Timestamp window (seconds)
    TimestampWindow = 300 // 5 minutes
)

// DIDAuthMiddleware verifies cryptographic signatures for DID claims.
func DIDAuthMiddleware(didWebService *services.DIDWebService) gin.HandlerFunc {
    return func(c *gin.Context) {
        callerDID := c.GetHeader(HeaderCallerDID)

        // No DID claimed - proceed without DID auth
        if callerDID == "" {
            c.Next()
            return
        }

        signature := c.GetHeader(HeaderDIDSignature)
        timestamp := c.GetHeader(HeaderDIDTimestamp)

        // DID claimed but signature missing
        if signature == "" || timestamp == "" {
            logger.Logger.Warn().
                Str("caller_did", callerDID).
                Msg("DID claimed but signature or timestamp missing")
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error":   "did_auth_required",
                "message": "DID claimed but signature or timestamp missing",
            })
            return
        }

        // Parse and validate timestamp
        ts, err := strconv.ParseInt(timestamp, 10, 64)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                "error":   "invalid_timestamp",
                "message": "Timestamp must be a Unix timestamp",
            })
            return
        }

        now := time.Now().Unix()
        if abs(now-ts) > TimestampWindow {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error":   "timestamp_expired",
                "message": fmt.Sprintf("Timestamp must be within %d seconds of current time", TimestampWindow),
            })
            return
        }

        // Read body for hash verification
        bodyBytes, err := io.ReadAll(c.Request.Body)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                "error":   "body_read_error",
                "message": "Failed to read request body",
            })
            return
        }
        // Restore body for downstream handlers
        c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

        // Build verification payload: "{timestamp}:{sha256(body)}"
        bodyHash := sha256.Sum256(bodyBytes)
        payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)

        // Decode signature
        sigBytes, err := base64.StdEncoding.DecodeString(signature)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
                "error":   "invalid_signature_encoding",
                "message": "Signature must be base64 encoded",
            })
            return
        }

        // Verify signature against DID document
        valid, err := didWebService.VerifyDIDOwnership(
            c.Request.Context(),
            callerDID,
            []byte(payload),
            sigBytes,
        )

        if err != nil {
            logger.Logger.Warn().
                Err(err).
                Str("caller_did", callerDID).
                Msg("DID verification failed")
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error":   "did_verification_failed",
                "message": "Failed to verify DID: " + err.Error(),
            })
            return
        }

        if !valid {
            logger.Logger.Warn().
                Str("caller_did", callerDID).
                Msg("Invalid DID signature")
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error":   "invalid_signature",
                "message": "Signature does not match DID public key",
            })
            return
        }

        // DID verified successfully
        logger.Logger.Debug().
            Str("caller_did", callerDID).
            Msg("DID signature verified")

        c.Set(ContextVerifiedDID, callerDID)
        c.Set(ContextDIDVerified, true)
        c.Next()
    }
}

// GetVerifiedDID retrieves the verified DID from context.
// Returns empty string if DID was not verified.
func GetVerifiedDID(c *gin.Context) string {
    did, exists := c.Get(ContextVerifiedDID)
    if !exists {
        return ""
    }
    return did.(string)
}

// IsDIDVerified returns true if the request has a verified DID.
func IsDIDVerified(c *gin.Context) bool {
    verified, exists := c.Get(ContextDIDVerified)
    if !exists {
        return false
    }
    return verified.(bool)
}

func abs(x int64) int64 {
    if x < 0 {
        return -x
    }
    return x
}
```

### 2.2 Create DID Auth Types

**File to Create:** `control-plane/pkg/types/did_auth_types.go`

```go
package types

// DIDAuthHeaders contains the headers used for DID authentication.
type DIDAuthHeaders struct {
    CallerDID    string `header:"X-Caller-DID"`
    DIDSignature string `header:"X-DID-Signature"`
    DIDTimestamp string `header:"X-DID-Timestamp"`
}

// DIDAuthError represents an authentication error.
type DIDAuthError struct {
    Error   string `json:"error"`
    Message string `json:"message"`
}

// DIDSignaturePayload represents the data that gets signed.
type DIDSignaturePayload struct {
    Timestamp int64  `json:"timestamp"`
    BodyHash  string `json:"body_hash"`
}
```

### 2.3 Register Middleware in Server

**File to Modify:** `control-plane/internal/server/server.go`

Add middleware registration:
```go
import (
    "github.com/Agent-Field/agentfield/control-plane/internal/middleware"
)

// In server setup, after creating didWebService:
didAuthMiddleware := middleware.DIDAuthMiddleware(didWebService)

// Apply to routes that need DID verification
// Option 1: Apply globally to all API routes
apiGroup := router.Group("/api/v1")
apiGroup.Use(didAuthMiddleware)

// Option 2: Apply only to specific routes
executeGroup := router.Group("/api/v1/execute")
executeGroup.Use(didAuthMiddleware)
```

### 2.4 Registration Must Never Return Private Keys

**Files to Modify:** SDK bootstrap and node registration payloads

Agent private keys are generated and stored locally by the agent runtime. Registration payloads may include DID/public key material, but must never include `private_key_jwk` in responses.

```go
response := gin.H{
    "agent_id":        agentID,
    "did":             did,
    "public_key_jwk":  publicKeyJWK,
    // ... other fields
}
```

---

## Phase 3: Storage Implementation (COMPLETED)

### 3.1 Add Methods to Storage Interface

**File to Modify:** `control-plane/internal/storage/storage.go`

Add to `StorageProvider` interface:
```go
// DID Document methods
StoreDIDDocument(ctx context.Context, record *types.DIDDocumentRecord) error
GetDIDDocument(ctx context.Context, did string) (*types.DIDDocumentRecord, error)
GetDIDDocumentByAgentID(ctx context.Context, agentID string) (*types.DIDDocumentRecord, error)
RevokeDIDDocument(ctx context.Context, did string) error
ListDIDDocuments(ctx context.Context) ([]*types.DIDDocumentRecord, error)

// Permission approval methods
CreatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
GetPermissionApproval(ctx context.Context, callerDID, targetDID string) (*types.PermissionApproval, error)
GetPermissionApprovalByID(ctx context.Context, id int64) (*types.PermissionApproval, error)
UpdatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
ListPermissionApprovals(ctx context.Context, status types.PermissionStatus) ([]*types.PermissionApproval, error)
ListAllPermissionApprovals(ctx context.Context) ([]*types.PermissionApproval, error)

// Protected agent rule methods
GetProtectedAgentRules(ctx context.Context) ([]*types.ProtectedAgentRule, error)
CreateProtectedAgentRule(ctx context.Context, rule *types.ProtectedAgentRule) error
DeleteProtectedAgentRule(ctx context.Context, id int64) error
UpdateProtectedAgentRule(ctx context.Context, rule *types.ProtectedAgentRule) error
```

### 3.2 Implement for Local Storage (SQLite)

**File to Modify:** `control-plane/internal/storage/local.go`

```go
// DID Document implementations

func (s *LocalStorageProvider) StoreDIDDocument(ctx context.Context, record *types.DIDDocumentRecord) error {
    query := `
        INSERT INTO did_documents (did, agent_id, did_document, public_key_jwk, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (did) DO UPDATE SET
            did_document = excluded.did_document,
            public_key_jwk = excluded.public_key_jwk,
            updated_at = excluded.updated_at
    `
    _, err := s.db.ExecContext(ctx, query,
        record.DID,
        record.AgentID,
        record.DIDDocument,
        record.PublicKeyJWK,
        record.CreatedAt,
        record.UpdatedAt,
    )
    return err
}

func (s *LocalStorageProvider) GetDIDDocument(ctx context.Context, did string) (*types.DIDDocumentRecord, error) {
    query := `
        SELECT did, agent_id, did_document, public_key_jwk, revoked_at, created_at, updated_at
        FROM did_documents
        WHERE did = ?
    `
    var record types.DIDDocumentRecord
    err := s.db.QueryRowContext(ctx, query, did).Scan(
        &record.DID,
        &record.AgentID,
        &record.DIDDocument,
        &record.PublicKeyJWK,
        &record.RevokedAt,
        &record.CreatedAt,
        &record.UpdatedAt,
    )
    if err != nil {
        return nil, err
    }
    return &record, nil
}

func (s *LocalStorageProvider) RevokeDIDDocument(ctx context.Context, did string) error {
    query := `UPDATE did_documents SET revoked_at = ? WHERE did = ?`
    _, err := s.db.ExecContext(ctx, query, time.Now(), did)
    return err
}

// Permission approval implementations

func (s *LocalStorageProvider) CreatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error {
    query := `
        INSERT INTO permission_approvals
        (caller_did, target_did, caller_agent_id, target_agent_id, status, reason, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `
    result, err := s.db.ExecContext(ctx, query,
        approval.CallerDID,
        approval.TargetDID,
        approval.CallerAgentID,
        approval.TargetAgentID,
        approval.Status,
        approval.Reason,
        approval.CreatedAt,
        approval.UpdatedAt,
    )
    if err != nil {
        return err
    }
    id, err := result.LastInsertId()
    if err != nil {
        return err
    }
    approval.ID = id
    return nil
}

func (s *LocalStorageProvider) GetPermissionApproval(ctx context.Context, callerDID, targetDID string) (*types.PermissionApproval, error) {
    query := `
        SELECT id, caller_did, target_did, caller_agent_id, target_agent_id, status,
               approved_by, approved_at, rejected_by, rejected_at, revoked_by, revoked_at,
               expires_at, reason, created_at, updated_at
        FROM permission_approvals
        WHERE caller_did = ? AND target_did = ?
    `
    var approval types.PermissionApproval
    err := s.db.QueryRowContext(ctx, query, callerDID, targetDID).Scan(
        &approval.ID,
        &approval.CallerDID,
        &approval.TargetDID,
        &approval.CallerAgentID,
        &approval.TargetAgentID,
        &approval.Status,
        &approval.ApprovedBy,
        &approval.ApprovedAt,
        &approval.RejectedBy,
        &approval.RejectedAt,
        &approval.RevokedBy,
        &approval.RevokedAt,
        &approval.ExpiresAt,
        &approval.Reason,
        &approval.CreatedAt,
        &approval.UpdatedAt,
    )
    if err != nil {
        return nil, err
    }
    return &approval, nil
}

func (s *LocalStorageProvider) UpdatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error {
    query := `
        UPDATE permission_approvals SET
            status = ?,
            approved_by = ?,
            approved_at = ?,
            rejected_by = ?,
            rejected_at = ?,
            revoked_by = ?,
            revoked_at = ?,
            expires_at = ?,
            reason = ?,
            updated_at = ?
        WHERE id = ?
    `
    _, err := s.db.ExecContext(ctx, query,
        approval.Status,
        approval.ApprovedBy,
        approval.ApprovedAt,
        approval.RejectedBy,
        approval.RejectedAt,
        approval.RevokedBy,
        approval.RevokedAt,
        approval.ExpiresAt,
        approval.Reason,
        approval.UpdatedAt,
        approval.ID,
    )
    return err
}

func (s *LocalStorageProvider) ListPermissionApprovals(ctx context.Context, status types.PermissionStatus) ([]*types.PermissionApproval, error) {
    query := `
        SELECT id, caller_did, target_did, caller_agent_id, target_agent_id, status,
               approved_by, approved_at, rejected_by, rejected_at, revoked_by, revoked_at,
               expires_at, reason, created_at, updated_at
        FROM permission_approvals
        WHERE status = ?
        ORDER BY created_at DESC
    `
    rows, err := s.db.QueryContext(ctx, query, status)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var approvals []*types.PermissionApproval
    for rows.Next() {
        var approval types.PermissionApproval
        err := rows.Scan(
            &approval.ID,
            &approval.CallerDID,
            &approval.TargetDID,
            &approval.CallerAgentID,
            &approval.TargetAgentID,
            &approval.Status,
            &approval.ApprovedBy,
            &approval.ApprovedAt,
            &approval.RejectedBy,
            &approval.RejectedAt,
            &approval.RevokedBy,
            &approval.RevokedAt,
            &approval.ExpiresAt,
            &approval.Reason,
            &approval.CreatedAt,
            &approval.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        approvals = append(approvals, &approval)
    }
    return approvals, nil
}

// Protected agent rule implementations

func (s *LocalStorageProvider) GetProtectedAgentRules(ctx context.Context) ([]*types.ProtectedAgentRule, error) {
    query := `
        SELECT id, pattern_type, pattern, description, enabled, created_at, updated_at
        FROM protected_agents_config
        WHERE enabled = true
        ORDER BY id
    `
    rows, err := s.db.QueryContext(ctx, query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var rules []*types.ProtectedAgentRule
    for rows.Next() {
        var rule types.ProtectedAgentRule
        err := rows.Scan(
            &rule.ID,
            &rule.PatternType,
            &rule.Pattern,
            &rule.Description,
            &rule.Enabled,
            &rule.CreatedAt,
            &rule.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        rules = append(rules, &rule)
    }
    return rules, nil
}

func (s *LocalStorageProvider) CreateProtectedAgentRule(ctx context.Context, rule *types.ProtectedAgentRule) error {
    query := `
        INSERT INTO protected_agents_config (pattern_type, pattern, description, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `
    result, err := s.db.ExecContext(ctx, query,
        rule.PatternType,
        rule.Pattern,
        rule.Description,
        rule.Enabled,
        rule.CreatedAt,
        rule.UpdatedAt,
    )
    if err != nil {
        return err
    }
    id, err := result.LastInsertId()
    if err != nil {
        return err
    }
    rule.ID = id
    return nil
}

func (s *LocalStorageProvider) DeleteProtectedAgentRule(ctx context.Context, id int64) error {
    query := `DELETE FROM protected_agents_config WHERE id = ?`
    _, err := s.db.ExecContext(ctx, query, id)
    return err
}
```

### 3.3 Implement for PostgreSQL

**File to Modify:** `control-plane/internal/storage/postgresql.go`

Same implementations as SQLite but with PostgreSQL syntax:
- Use `$1, $2, ...` instead of `?` for parameters
- Use `RETURNING id` instead of `LastInsertId()`
- Adjust any SQLite-specific syntax

---

## Phase 4: API Endpoints (COMPLETED)

### 4.1 Create Permission Handlers

**File to Create:** `control-plane/internal/handlers/permissions.go`

```go
package handlers

import (
    "net/http"
    "strconv"

    "github.com/Agent-Field/agentfield/control-plane/internal/middleware"
    "github.com/Agent-Field/agentfield/control-plane/internal/services"
    "github.com/Agent-Field/agentfield/control-plane/pkg/types"
    "github.com/gin-gonic/gin"
)

type PermissionHandlers struct {
    permissionService *services.PermissionService
}

func NewPermissionHandlers(permissionService *services.PermissionService) *PermissionHandlers {
    return &PermissionHandlers{
        permissionService: permissionService,
    }
}

// RequestPermission handles permission request creation
// POST /api/v1/permissions/request
func (h *PermissionHandlers) RequestPermission(c *gin.Context) {
    var req types.PermissionRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    approval, err := h.permissionService.RequestPermission(c.Request.Context(), &req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, approval)
}

// CheckPermission checks if permission exists
// GET /api/v1/permissions/check?caller_did=...&target_did=...&target_agent_id=...
func (h *PermissionHandlers) CheckPermission(c *gin.Context) {
    callerDID := c.Query("caller_did")
    targetDID := c.Query("target_did")
    targetAgentID := c.Query("target_agent_id")

    if callerDID == "" || targetDID == "" || targetAgentID == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "caller_did, target_did, and target_agent_id are required"})
        return
    }

    // Resolve target tags from canonical source (agent registry)
    targetTags := canonicalPlainTagsFromAgent(targetAgentID)

    check, err := h.permissionService.CheckPermission(
        c.Request.Context(),
        callerDID,
        targetDID,
        targetAgentID,
        targetTags,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, check)
}

// GetPermissionVC returns the VC for an approved permission
// GET /api/v1/permissions/:id/vc
func (h *PermissionHandlers) GetPermissionVC(c *gin.Context) {
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
        return
    }

    // Get approval and generate VC
    // TODO: Implement
    _ = id
    c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (h *PermissionHandlers) RegisterRoutes(router *gin.RouterGroup) {
    permGroup := router.Group("/permissions")
    {
        permGroup.POST("/request", h.RequestPermission)
        permGroup.GET("/check", h.CheckPermission)
        permGroup.GET("/:id/vc", h.GetPermissionVC)
    }
}
```

### 4.2 Create Admin Permission Handlers

**File to Create:** `control-plane/internal/handlers/admin/permissions.go`

```go
package admin

import (
    "net/http"
    "strconv"

    "github.com/Agent-Field/agentfield/control-plane/internal/services"
    "github.com/Agent-Field/agentfield/control-plane/pkg/types"
    "github.com/gin-gonic/gin"
)

type PermissionAdminHandlers struct {
    permissionService *services.PermissionService
}

func NewPermissionAdminHandlers(permissionService *services.PermissionService) *PermissionAdminHandlers {
    return &PermissionAdminHandlers{
        permissionService: permissionService,
    }
}

// ListPendingPermissions returns all pending permission requests
// GET /api/v1/admin/permissions/pending
func (h *PermissionAdminHandlers) ListPendingPermissions(c *gin.Context) {
    permissions, err := h.permissionService.ListPendingPermissions(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, types.PermissionListResponse{
        Permissions: permissions,
        Total:       len(permissions),
    })
}

// ListAllPermissions returns all permissions
// GET /api/v1/admin/permissions
func (h *PermissionAdminHandlers) ListAllPermissions(c *gin.Context) {
    permissions, err := h.permissionService.ListAllPermissions(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, types.PermissionListResponse{
        Permissions: permissions,
        Total:       len(permissions),
    })
}

// ApprovePermission approves a pending permission
// POST /api/v1/admin/permissions/:id/approve
func (h *PermissionAdminHandlers) ApprovePermission(c *gin.Context) {
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
        return
    }

    var req types.PermissionApproveRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    // Get approver from context (would come from auth middleware)
    approvedBy := "admin" // TODO: Get from auth context

    approval, err := h.permissionService.ApprovePermission(
        c.Request.Context(),
        id,
        approvedBy,
        req.DurationHours,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, approval)
}

// RejectPermission rejects a pending permission
// POST /api/v1/admin/permissions/:id/reject
func (h *PermissionAdminHandlers) RejectPermission(c *gin.Context) {
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
        return
    }

    var req types.PermissionRejectRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    rejectedBy := "admin" // TODO: Get from auth context

    approval, err := h.permissionService.RejectPermission(
        c.Request.Context(),
        id,
        rejectedBy,
        req.Reason,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, approval)
}

// RevokePermission revokes an approved permission
// POST /api/v1/admin/permissions/:id/revoke
func (h *PermissionAdminHandlers) RevokePermission(c *gin.Context) {
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid permission ID"})
        return
    }

    var req types.PermissionRevokeRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    revokedBy := "admin" // TODO: Get from auth context

    approval, err := h.permissionService.RevokePermission(
        c.Request.Context(),
        id,
        revokedBy,
        req.Reason,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, approval)
}

// ListProtectedAgentRules returns all protected agent rules
// GET /api/v1/admin/protected-agents
func (h *PermissionAdminHandlers) ListProtectedAgentRules(c *gin.Context) {
    rules, err := h.permissionService.ListProtectedAgentRules(c.Request.Context())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, types.ProtectedAgentListResponse{
        Rules: rules,
        Total: len(rules),
    })
}

// AddProtectedAgentRule adds a new protected agent rule
// POST /api/v1/admin/protected-agents
func (h *PermissionAdminHandlers) AddProtectedAgentRule(c *gin.Context) {
    var req types.ProtectedAgentRuleRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    rule, err := h.permissionService.AddProtectedAgentRule(c.Request.Context(), &req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, rule)
}

// RemoveProtectedAgentRule removes a protected agent rule
// DELETE /api/v1/admin/protected-agents/:id
func (h *PermissionAdminHandlers) RemoveProtectedAgentRule(c *gin.Context) {
    idStr := c.Param("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
        return
    }

    if err := h.permissionService.RemoveProtectedAgentRule(c.Request.Context(), id); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Rule deleted"})
}

func (h *PermissionAdminHandlers) RegisterRoutes(router *gin.RouterGroup) {
    adminGroup := router.Group("/admin")
    {
        permGroup := adminGroup.Group("/permissions")
        {
            permGroup.GET("", h.ListAllPermissions)
            permGroup.GET("/pending", h.ListPendingPermissions)
            permGroup.POST("/:id/approve", h.ApprovePermission)
            permGroup.POST("/:id/reject", h.RejectPermission)
            permGroup.POST("/:id/revoke", h.RevokePermission)
        }

        protectedGroup := adminGroup.Group("/protected-agents")
        {
            protectedGroup.GET("", h.ListProtectedAgentRules)
            protectedGroup.POST("", h.AddProtectedAgentRule)
            protectedGroup.DELETE("/:id", h.RemoveProtectedAgentRule)
        }
    }
}
```

### 4.3 Register Routes in Server

**File to Modify:** `control-plane/internal/server/server.go`

```go
// Create handlers
permissionHandlers := handlers.NewPermissionHandlers(permissionService)
permissionAdminHandlers := admin.NewPermissionAdminHandlers(permissionService)

// Register routes
permissionHandlers.RegisterRoutes(apiGroup)
permissionAdminHandlers.RegisterRoutes(apiGroup)
```

---

## Phase 5: Execute Handler Integration (COMPLETED)

### 5.1 Add Permission Check to Execute

**File to Modify:** `control-plane/internal/handlers/execute.go` (or `reasoners.go`)

Find the execute handler and add permission check:

```go
func (h *ExecuteHandler) Execute(c *gin.Context) {
    // ... existing code to parse request and resolve target agent ...

    // Get verified caller DID from middleware
    callerDID := middleware.GetVerifiedDID(c)

    // Get target agent info
    targetDID := targetAgent.DID
    targetAgentID := targetAgent.ID
    targetTags := targetAgent.Tags

    // Check if permission is required and valid
    if h.permissionService != nil && h.permissionService.IsEnabled() {
        check, err := h.permissionService.CheckPermission(
            c.Request.Context(),
            callerDID,
            targetDID,
            targetAgentID,
            targetTags,
        )
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error": "Permission check failed: " + err.Error(),
            })
            return
        }

        if check.RequiresPermission && !check.HasValidApproval {
            // Auto-create permission request if configured
            if h.permissionService.Config().AutoRequestOnDeny {
                _, _ = h.permissionService.RequestPermission(c.Request.Context(), &types.PermissionRequest{
                    CallerDID:     callerDID,
                    TargetDID:     targetDID,
                    CallerAgentID: callerAgentID,
                    TargetAgentID: targetAgentID,
                    Reason:        "Auto-requested on denied call",
                })
            }

            status := http.StatusForbidden
            response := gin.H{
                "error":              "permission_required",
                "message":            "Permission required to call this agent",
                "requires_permission": true,
                "approval_status":    check.ApprovalStatus,
            }

            if check.ApprovalID != nil {
                response["approval_id"] = *check.ApprovalID
            }

            c.JSON(status, response)
            return
        }
    }

    // ... continue with execution ...
}
```

---

## Phase 6: Configuration (COMPLETED)

### 6.1 Add Permission Config to Config Struct

**File to Modify:** `control-plane/internal/config/config.go`

```go
type DIDConfig struct {
    // ... existing fields ...
    Authorization AuthorizationConfig `yaml:"authorization" mapstructure:"authorization"`
}

type AuthorizationConfig struct {
    Enabled                     bool                   `yaml:"enabled" mapstructure:"enabled"`
    DIDAuthEnabled              bool                   `yaml:"did_auth_enabled" mapstructure:"did_auth_enabled"`
    Domain                      string                 `yaml:"domain" mapstructure:"domain"`
    TimestampWindowSeconds      int64                  `yaml:"timestamp_window_seconds" mapstructure:"timestamp_window_seconds"`
    DefaultApprovalDurationHours int                   `yaml:"default_approval_duration_hours" mapstructure:"default_approval_duration_hours"`
    AutoRequestOnDeny           bool                   `yaml:"auto_request_on_deny" mapstructure:"auto_request_on_deny"`
    ProtectedAgents             []ProtectedAgentConfig `yaml:"protected_agents" mapstructure:"protected_agents"`
}

type ProtectedAgentConfig struct {
    PatternType string `yaml:"pattern_type" mapstructure:"pattern_type"`
    Pattern     string `yaml:"pattern" mapstructure:"pattern"`
    Description string `yaml:"description" mapstructure:"description"`
}
```

### 6.2 Load Protected Agents from Config

**File to Modify:** `control-plane/internal/server/server.go`

```go
// After loading config, seed protected agent rules from config
if cfg.Features.DID.Authorization.Enabled && len(cfg.Features.DID.Authorization.ProtectedAgents) > 0 {
    for _, rule := range cfg.Features.DID.Authorization.ProtectedAgents {
        _, err := permissionService.AddProtectedAgentRule(ctx, &types.ProtectedAgentRuleRequest{
            PatternType: types.ProtectedAgentPatternType(rule.PatternType),
            Pattern:     rule.Pattern,
            Description: rule.Description,
        })
        if err != nil {
            // Log but don't fail - might already exist
            logger.Logger.Debug().Err(err).Msg("Failed to add protected agent rule from config")
        }
    }
}
```

### 6.3 Example Config File

**File:** `control-plane/config/agentfield.yaml`

```yaml
# ... existing config ...

features:
  did:
    authorization:
      enabled: true
      did_auth_enabled: true
      domain: "localhost:8080"
      default_approval_duration_hours: 720  # 30 days
      auto_request_on_deny: true
      protected_agents:
        - pattern_type: tag
          pattern: admin
          description: "Admin-tagged agents require permission"
        - pattern_type: tag_pattern
          pattern: "finance*"
          description: "Finance agents require permission"
        - pattern_type: agent_id
          pattern: "payment-gateway"
          description: "Payment gateway requires permission"
```

---

## Phase 7: Admin UI (COMPLETED)

### 7.1 UI Routes to Create

**Directory:** `control-plane/web/client/src/routes/permissions/`

| File | Purpose |
|------|---------|
| `PendingPermissions.tsx` | List and approve/reject pending requests |
| `ActivePermissions.tsx` | List approved permissions, revoke option |
| `PermissionHistory.tsx` | Full history of all permission changes |
| `ProtectedAgents.tsx` | Manage protected agent rules |

### 7.2 UI Components

Key components needed:
- Permission request card (shows caller/target, approve/reject buttons)
- Permission table (sortable, filterable)
- Protected agent rule form (add new rules)
- Confirmation dialogs for approve/reject/revoke

### 7.3 API Integration

```typescript
// api/permissions.ts
export const permissionsApi = {
  listPending: () => fetch('/api/v1/admin/permissions/pending'),
  listAll: () => fetch('/api/v1/admin/permissions'),
  approve: (id: number, duration?: number) =>
    fetch(`/api/v1/admin/permissions/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ duration_hours: duration }),
    }),
  reject: (id: number, reason?: string) =>
    fetch(`/api/v1/admin/permissions/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  revoke: (id: number, reason?: string) =>
    fetch(`/api/v1/admin/permissions/${id}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
};

export const protectedAgentsApi = {
  list: () => fetch('/api/v1/admin/protected-agents'),
  add: (rule: ProtectedAgentRule) =>
    fetch('/api/v1/admin/protected-agents', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  remove: (id: number) =>
    fetch(`/api/v1/admin/protected-agents/${id}`, { method: 'DELETE' }),
};
```

---

## Phase 8: SDK Updates (COMPLETED)

### 8.1 Python SDK Changes

**File to Modify:** `sdk/python/agentfield/client.py`

```python
import hashlib
import time
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

class AgentFieldClient:
    def __init__(self, server_url: str, agent_id: str, did: str = None, private_key: str = None):
        self.server_url = server_url
        self.agent_id = agent_id
        self.did = did
        self._private_key = self._load_private_key(private_key) if private_key else None

    def _load_private_key(self, private_key_jwk: str) -> Ed25519PrivateKey:
        """Load Ed25519 private key from JWK format."""
        import json
        jwk = json.loads(private_key_jwk)
        # Extract 'd' (private key) from JWK
        d_bytes = base64.urlsafe_b64decode(jwk['d'] + '==')
        return Ed25519PrivateKey.from_private_bytes(d_bytes)

    def _sign_request(self, body: bytes) -> tuple[str, str]:
        """Sign request body and return (signature, timestamp)."""
        if not self._private_key:
            return None, None

        timestamp = str(int(time.time()))
        body_hash = hashlib.sha256(body).hexdigest()
        payload = f"{timestamp}:{body_hash}".encode()

        signature = self._private_key.sign(payload)
        signature_b64 = base64.b64encode(signature).decode()

        return signature_b64, timestamp

    async def execute(self, target: str, input_data: dict) -> dict:
        """Execute a call to another agent."""
        import json
        import aiohttp

        body = json.dumps({
            "target": target,
            "input": input_data,
        }).encode()

        headers = {
            "Content-Type": "application/json",
        }

        # Add DID authentication headers if we have a private key
        if self.did and self._private_key:
            signature, timestamp = self._sign_request(body)
            headers["X-Caller-DID"] = self.did
            headers["X-DID-Signature"] = signature
            headers["X-DID-Timestamp"] = timestamp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.server_url}/api/v1/execute",
                data=body,
                headers=headers,
            ) as response:
                return await response.json()
```

**File to Modify:** `sdk/python/agentfield/agent.py`

```python
class Agent:
    def __init__(
        self,
        node_id: str,
        tags: list[str] = None,
        dependencies: list[str] = None,
        private_key: str = None,
        **kwargs
    ):
        self.node_id = node_id
        self.tags = tags or []
        self.dependencies = dependencies or []
        self._private_key = private_key or os.environ.get("AGENTFIELD_PRIVATE_KEY")
        self.did = None
        # ... rest of init

    async def register(self):
        """Register agent with control plane."""
        response = await self._client.post("/api/v1/agents/register", json={
            "agent_id": self.node_id,
            "tags": self.tags,
            "dependencies": self.dependencies,
        })

        data = response.json()
        self.did = data.get("did")

        # Private keys are never returned by the control plane.
        # Agent must already be configured with local key material.

        # Log pending permissions
        if "pending_permissions" in data:
            for perm in data["pending_permissions"]:
                logger.info(f"Permission pending for tag '{perm['target_tag']}': {perm['status']}")

        return data
```

### 8.2 Go SDK Changes

**File to Modify:** `sdk/go/client/client.go`

```go
package client

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "time"
)

type Client struct {
    serverURL  string
    agentID    string
    did        string
    privateKey ed25519.PrivateKey
    httpClient *http.Client
}

type ClientOption func(*Client)

func WithPrivateKey(privateKeyJWK string) ClientOption {
    return func(c *Client) {
        key, err := parsePrivateKeyJWK(privateKeyJWK)
        if err == nil {
            c.privateKey = key
        }
    }
}

func (c *Client) signRequest(body []byte) (signature string, timestamp string) {
    if c.privateKey == nil {
        return "", ""
    }

    ts := strconv.FormatInt(time.Now().Unix(), 10)
    bodyHash := sha256.Sum256(body)
    payload := fmt.Sprintf("%s:%x", ts, bodyHash)

    sig := ed25519.Sign(c.privateKey, []byte(payload))
    return base64.StdEncoding.EncodeToString(sig), ts
}

func (c *Client) Execute(target string, input map[string]interface{}) (map[string]interface{}, error) {
    body, err := json.Marshal(map[string]interface{}{
        "target": target,
        "input":  input,
    })
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest("POST", c.serverURL+"/api/v1/execute", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")

    // Add DID authentication headers
    if c.did != "" && c.privateKey != nil {
        signature, timestamp := c.signRequest(body)
        req.Header.Set("X-Caller-DID", c.did)
        req.Header.Set("X-DID-Signature", signature)
        req.Header.Set("X-DID-Timestamp", timestamp)
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result, nil
}

func parsePrivateKeyJWK(jwkJSON string) (ed25519.PrivateKey, error) {
    var jwk struct {
        D string `json:"d"`
    }
    if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
        return nil, err
    }

    privateKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
    if err != nil {
        return nil, err
    }

    return ed25519.NewKeyFromSeed(privateKeyBytes), nil
}
```

---

## Testing Strategy

### Unit Tests

| Test File | Coverage |
|-----------|----------|
| `permission_service_test.go` | Permission check logic, approval flow |
| `did_web_service_test.go` | DID generation, resolution, signature verification |
| `did_auth_middleware_test.go` | Signature validation, timestamp checks |
| `storage_permissions_test.go` | Database operations |

### Integration Tests

| Test | Description |
|------|-------------|
| Registration with dependencies | Agent registers, pending permissions created |
| Full approval flow | Request → approve → call succeeds |
| Rejection flow | Request → reject → call fails |
| Revocation flow | Approved → revoke → call fails |
| Expiration | Approved with duration → expires → call fails |
| DID spoofing | Invalid signature rejected |
| Replay attack | Old timestamp rejected |

### Manual Testing Checklist

1. Start control plane with `permissions.enabled: true`
2. Configure a protected agent (tag: "admin")
3. Register Agent A (no admin tag)
4. Register Agent B (has admin tag)
5. Agent A tries to call Agent B → gets "permission required"
6. Check admin UI shows pending request
7. Approve in UI with 30-day duration
8. Agent A calls Agent B → succeeds
9. Revoke in UI
10. Agent A calls Agent B → fails

---

## Migration & Rollout

### Phase 1: Deploy Disabled
- Deploy with `permissions.enabled: false`
- Run migrations
- Verify no impact on existing functionality

### Phase 2: Shadow Mode
- Enable permission checking but only log violations
- Don't block calls
- Monitor for false positives

### Phase 3: Gradual Enablement
- Enable for specific protected agents (start with test agents)
- Monitor admin queue
- Train admins on approval workflow

### Phase 4: Full Enablement
- Enable for all configured protected agents
- Monitor and adjust

### Rollback Plan
- Set `permissions.enabled: false` to disable immediately
- All calls proceed as before
- No data loss (approvals preserved for re-enablement)

---

## File Reference

### Created Files

| File | Purpose |
|------|---------|
| `docs/VC_AUTHORIZATION_ARCHITECTURE.md` | Architecture overview |
| `docs/DID_AUTHENTICATION_SECURITY.md` | Security model |
| `docs/VC_AUTHORIZATION_IMPLEMENTATION_GUIDE.md` | This document |
| `migrations/018_create_permission_approvals.sql` | Approvals table |
| `migrations/019_create_did_documents.sql` | DID documents table |
| `migrations/020_create_protected_agents.sql` | Protection rules table |
| `pkg/types/permission_types.go` | Permission type definitions |
| `pkg/types/did_web_types.go` | DID type definitions |
| `internal/services/did_web_service.go` | DID Web service |
| `internal/services/permission_service.go` | Permission service |

### Files to Create

| File | Purpose |
|------|---------|
| `internal/middleware/did_auth.go` | DID signature verification |
| `pkg/types/did_auth_types.go` | Auth type definitions |
| `internal/handlers/permissions.go` | Permission API handlers |
| `internal/handlers/admin/permissions.go` | Admin API handlers |

### Files to Modify

| File | Changes |
|------|---------|
| `internal/storage/storage.go` | Add storage interface methods |
| `internal/storage/local.go` | Implement for SQLite |
| `internal/storage/postgresql.go` | Implement for PostgreSQL |
| `internal/server/server.go` | Register middleware and routes |
| `internal/handlers/nodes.go` | Return DID/public key material only (no private keys) |
| `internal/handlers/execute.go` | Add permission check |
| `internal/config/config.go` | Add permission config |
| `sdk/python/agentfield/client.py` | Sign requests |
| `sdk/python/agentfield/agent.py` | Handle dependencies |
| `sdk/go/client/client.go` | Sign requests |

---

*End of Implementation Guide*
