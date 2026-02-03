# PRD: Tag-Based Access Control for AgentField

**Version:** 2.0
**Status:** Draft
**Date:** January 2025

---

## Executive Summary

This document specifies a tag-based access control system for AgentField that enables fine-grained authorization over agent interactions. The system uses a consent-based model where agents self-assign tags to declare which API key scopes can access them.

**Core Philosophy:** Agents opt-in to access via tags. Admins scope API keys. The control plane enforces at the edge.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Goals and Non-Goals](#goals-and-non-goals)
3. [Architecture Overview](#architecture-overview)
4. [Data Model](#data-model)
5. [Access Control Model](#access-control-model)
6. [Configuration](#configuration)
7. [Discovery Integration](#discovery-integration)
8. [REST API Specification](#rest-api-specification)
9. [Security Considerations](#security-considerations)
10. [Implementation Phases](#implementation-phases)
11. [Success Metrics](#success-metrics)

---

## Problem Statement

### Current State

AgentField provides robust infrastructure for multi-agent systems:
- **Identity:** Every agent, reasoner, and skill has a cryptographic DID
- **Audit:** Verifiable Credentials (VCs) prove execution provenance
- **Discovery:** Agents can discover and call other agents via tags
- **Memory:** Scoped memory with workflow/session/global levels

### Gap

There is no authorization layer between identity and action:
- Single global API key provides all-or-nothing access
- Any holder of the API key can call any agent's reasoners
- No way to scope access for different teams or use cases
- Discovery shows all agents regardless of caller permissions
- Cannot isolate access for multi-tenant deployments

### Impact

- **Security:** No defense-in-depth for sensitive operations
- **Multi-tenancy:** Cannot isolate teams at the infrastructure level
- **Operational:** Cannot delegate limited access to external integrations
- **Compliance:** Cannot restrict access to sensitive agents (PCI, HIPAA, etc.)

---

## Goals and Non-Goals

### Goals

1. **Scoped API keys** — Keys with limited access to specific tags
2. **Consent-based access** — Agents opt-in by self-assigning tags
3. **Pattern matching** — Support wildcards (`finance*`, `*-internal`) for flexible scoping
4. **Two-layer discovery** — Permissions filter first, then tags filter
5. **Central enforcement** — Control plane enforces at every hop
6. **Fail-closed default** — Scoped keys can only access matching tags
7. **No breaking SDK changes** — Existing tag mechanism reused; internal SDK changes are transparent
8. **Secure key propagation** — Signed headers prevent forgery during workflow execution

### Non-Goals

1. **Complex policy rules** — No conditional expressions or Rego
2. **Role hierarchies** — Flat tag-based model only
3. **Hot-reload of YAML config** — Config file changes require restart (API-created keys are immediate)

---

## Architecture Overview

### System Context

```
┌─────────────────────────────────────────────────────────────────────┐
│                     External Request (API Key)                       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Control Plane (Go)                           │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Auth Middleware                             │  │
│  │                                                                │  │
│  │  1. Extract API key from request                              │  │
│  │  2. Look up key → scopes mapping                              │  │
│  │  3. Attach scopes to request context                          │  │
│  │                                                                │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                    │                                 │
│                                    ▼                                 │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                 Execution / Discovery Handler                  │  │
│  │                                                                │  │
│  │  4. Get target agent's tags                                   │  │
│  │  5. Check: key.scopes ∩ agent.tags ≠ ∅                        │  │
│  │  6. If no match → 403 Forbidden                               │  │
│  │  7. If match → proceed with request                           │  │
│  │                                                                │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              ┌─────────┐    ┌─────────┐    ┌─────────┐
              │ Agent A │    │ Agent B │    │ Agent C │
              │         │    │         │    │         │
              │ Tags:   │    │ Tags:   │    │ Tags:   │
              │[finance]│    │[finance]│    │ [admin] │
              │ [pci]   │    │  [hr]   │    │         │
              └─────────┘    └─────────┘    └─────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Access primitive | Tags | Already exist on reasoners/skills; zero new concepts |
| Key scoping | Tag patterns | Intuitive: "this key accesses finance-tagged agents" |
| Enforcement point | Control plane edge | Single point; internal calls trusted |
| Consent model | Self-assigned tags | Agents opt-in; can't grant access to others |
| Default stance | Fail-closed for scoped keys | Super keys allow all; scoped keys require match |
| Key propagation | Single key through workflow | Same key checked at every hop in the chain |
| Configuration | YAML file | Version-controllable, auditable, no external deps |

---

## Data Model

### Core Types

```go
// APIKey represents an authentication key with optional scope restrictions.
type APIKey struct {
    ID          string     `json:"id" yaml:"id"`
    Name        string     `json:"name" yaml:"name"`
    KeyHash     string     `json:"-" yaml:"-"`           // bcrypt hash, never exposed

    // Scopes define what tags this key can access.
    // Empty slice or ["*"] = super key (full access)
    // ["finance", "shared"] = individual tags
    // ["finance*"] = wildcard pattern
    // ["@payment-workflow"] = scope group (expands to multiple tags)
    Scopes      []string   `json:"scopes" yaml:"scopes"`

    // Metadata
    Description string     `json:"description,omitempty" yaml:"description,omitempty"`
    CreatedAt   time.Time  `json:"created_at" yaml:"-"`
    ExpiresAt   *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
    LastUsedAt  *time.Time `json:"last_used_at,omitempty" yaml:"-"`
    Enabled     bool       `json:"enabled" yaml:"enabled"`
}

// ScopeGroup defines a named group of tags for workflow-level access.
type ScopeGroup struct {
    Name        string   `json:"name" yaml:"name"`
    Tags        []string `json:"tags" yaml:"tags"`
    Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// KeyType derived from scopes
func (k *APIKey) IsSuperKey() bool {
    return len(k.Scopes) == 0 || (len(k.Scopes) == 1 && k.Scopes[0] == "*")
}

// ExpandScopes resolves scope groups and returns all effective tags.
func (k *APIKey) ExpandScopes(groups map[string]ScopeGroup) []string {
    expanded := make([]string, 0)
    for _, scope := range k.Scopes {
        if strings.HasPrefix(scope, "@") {
            groupName := strings.TrimPrefix(scope, "@")
            if group, ok := groups[groupName]; ok {
                expanded = append(expanded, group.Tags...)
            }
        } else {
            expanded = append(expanded, scope)
        }
    }
    return expanded
}
```

### Tag Resolution

Tags are resolved from the `AgentNode` structure. An agent's effective tags are the union of:
1. **Agent-level tags** — Declared when creating the agent (e.g., `Agent(tags=["finance"])`)
2. **Reasoner tags** — Declared on individual reasoners
3. **Skill tags** — Declared on individual skills

```go
// AgentNode now includes a Tags field
type AgentNode struct {
    ID       string   `json:"id" db:"id"`
    Tags     []string `json:"tags,omitempty" db:"tags"` // Agent-level tags
    Reasoners []ReasonerDefinition `json:"reasoners"`
    Skills    []SkillDefinition    `json:"skills"`
    // ... other fields
}

// GetAgentTags returns all unique tags for an agent (agent + reasoners + skills)
func GetAgentTags(agent *AgentNode) []string {
    tagSet := make(map[string]struct{})

    // Agent-level tags
    for _, t := range agent.Tags {
        tagSet[t] = struct{}{}
    }
    // Reasoner tags
    for _, r := range agent.Reasoners {
        for _, t := range r.Tags {
            tagSet[t] = struct{}{}
        }
    }
    // Skill tags
    for _, s := range agent.Skills {
        for _, t := range s.Tags {
            tagSet[t] = struct{}{}
        }
    }

    tags := make([]string, 0, len(tagSet))
    for t := range tagSet {
        tags = append(tags, t)
    }
    return tags
}
```

### Database Schema

```sql
-- API keys table (for PostgreSQL mode)
CREATE TABLE api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_hash        TEXT NOT NULL,          -- bcrypt hash
    scopes          JSONB NOT NULL DEFAULT '[]',
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE,
    last_used_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_name ON api_keys(name);
CREATE INDEX idx_api_keys_enabled ON api_keys(enabled);

-- Audit log for access decisions (optional, for compliance)
CREATE TABLE access_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    api_key_id      TEXT NOT NULL,
    api_key_name    TEXT NOT NULL,
    target_agent    TEXT NOT NULL,
    target_reasoner TEXT,
    agent_tags      JSONB NOT NULL,
    key_scopes      JSONB NOT NULL,
    allowed         BOOLEAN NOT NULL,
    deny_reason     TEXT
);

CREATE INDEX idx_access_audit_timestamp ON access_audit_log(timestamp DESC);
CREATE INDEX idx_access_audit_key ON access_audit_log(api_key_id);
CREATE INDEX idx_access_audit_allowed ON access_audit_log(allowed);
```

---

## Access Control Model

### Tag Matching Algorithm

```go
// CanAccess checks if an API key can access an agent based on tag matching.
func (k *APIKey) CanAccess(agentTags []string) bool {
    // Super keys can access everything
    if k.IsSuperKey() {
        return true
    }

    // Scoped keys require at least one scope to match at least one tag
    for _, scope := range k.Scopes {
        for _, tag := range agentTags {
            if matchesPattern(scope, tag) {
                return true
            }
        }
    }

    return false
}

// matchesPattern checks if a scope pattern matches a tag.
// Supports:
//   - Exact match: "finance" matches "finance"
//   - Prefix wildcard: "finance*" matches "finance", "finance-internal", "finance-pci"
//   - Full wildcard: "*" matches anything
func matchesPattern(pattern, tag string) bool {
    if pattern == "*" {
        return true
    }
    if strings.HasSuffix(pattern, "*") {
        prefix := strings.TrimSuffix(pattern, "*")
        return strings.HasPrefix(tag, prefix)
    }
    return pattern == tag
}
```

### Enforcement Points

#### 1. Execution Requests

```go
// In execute handler
func (h *ExecuteHandler) Execute(c *gin.Context) {
    // Get key scopes from context (set by auth middleware)
    scopes := getKeyScopes(c)

    // Get target agent
    agent, err := h.storage.GetAgent(ctx, agentID)
    if err != nil {
        // ... handle error
    }

    // Check access
    agentTags := GetAgentTags(agent)
    if !canAccessWithScopes(scopes, agentTags) {
        c.JSON(http.StatusForbidden, gin.H{
            "error":   "access_denied",
            "message": "API key does not have access to this agent",
            "agent":   agentID,
            "hint":    "Agent requires one of these tags: " + strings.Join(agentTags, ", "),
        })
        return
    }

    // Proceed with execution...
}
```

#### 2. Discovery Requests

```go
// In discovery handler - filter results by permission
func (h *DiscoveryHandler) filterByPermission(agents []*AgentNode, scopes []string) []*AgentNode {
    // Super keys see everything
    if isSuperKey(scopes) {
        return agents
    }

    // Scoped keys only see matching agents
    permitted := make([]*AgentNode, 0)
    for _, agent := range agents {
        agentTags := GetAgentTags(agent)
        if canAccessWithScopes(scopes, agentTags) {
            permitted = append(permitted, agent)
        }
    }
    return permitted
}
```

### Key Propagation Through Workflows

**Important:** The same API key is propagated and checked at every hop in the workflow.

```
External Request (with API key sk_payment_workflow)
  Key scopes: ["@payment-workflow"] → expands to ["finance", "audit", "notification"]
    │
    ▼
┌─────────────────────────────────────────┐
│ Control Plane - Permission Check #1     │
│ Target: finance-agent (tags: [finance]) │
│ Check: "finance" in expanded scopes?    │
│ Result: ALLOWED ✓                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ finance-agent executes                   │
│ Calls: audit-agent.log_transaction()    │
│ Key sk_payment_workflow propagated      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ Control Plane - Permission Check #2     │
│ Target: audit-agent (tags: [audit])     │
│ Check: "audit" in expanded scopes?      │
│ Result: ALLOWED ✓                       │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ audit-agent executes                     │
│ Calls: notification-agent.send()        │
│ Key sk_payment_workflow propagated      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ Control Plane - Permission Check #3     │
│ Target: notification-agent (tags: [notification]) │
│ Check: "notification" in expanded scopes? │
│ Result: ALLOWED ✓                       │
└─────────────────────────────────────────┘
```

**Key propagation is automatic:** The control plane passes the API key context through workflow headers, so agents don't need to manage keys themselves.

**Scope groups simplify workflow access:** Instead of listing every agent, define a workflow scope group once and reference it in keys.

### Key Propagation Security

Key context is propagated via HTTP headers with HMAC-SHA256 signature verification to prevent forgery:

| Header | Purpose |
|--------|---------|
| `X-AgentField-Key-ID` | Key identifier |
| `X-AgentField-Key-Name` | Human-readable key name |
| `X-AgentField-Key-Scopes` | JSON-encoded scopes array |
| `X-AgentField-Key-Sig` | HMAC-SHA256 signature |
| `X-AgentField-Key-TS` | Timestamp (replay prevention) |

**How it works:**
1. Control plane signs key context with a secret before forwarding to agents
2. Agent SDKs capture and forward these headers on subsequent calls
3. Control plane verifies signature before trusting propagated context
4. Timestamp prevents replay attacks (configurable max age, default 5 minutes)

**Security properties:**
- Agents cannot forge key context (don't know the signing secret)
- Replay attacks prevented via timestamp validation
- Standard HMAC-SHA256 - no external dependencies

---

## Configuration

### YAML Configuration Format

API keys are configured in `agentfield.yaml`:

```yaml
api:
  auth:
    # Legacy single key (for backwards compatibility)
    # If set, this becomes a super key named "default"
    api_key: ""

    # Secret for signing key propagation headers (auto-generated if empty)
    # Set via env: AGENTFIELD_KEY_PROPAGATION_SECRET
    propagation_secret: ""

    # Enable audit logging of access decisions
    audit_enabled: false

    # Scope groups - define workflow-level access
    scope_groups:
      payment-workflow:
        tags: ["finance", "audit", "notification", "billing"]
        description: "All agents involved in payment processing"

      reporting-workflow:
        tags: ["finance", "reporting", "analytics", "shared"]
        description: "All agents for financial reporting"

      customer-support:
        tags: ["support", "crm", "notification", "shared"]
        description: "Customer support workflow agents"

    # API keys
    keys:
      # Super key - full access to everything
      - name: admin
        # key value set via env: AGENTFIELD_API_KEY_ADMIN
        scopes: ["*"]
        description: "Admin key with full access"

      # Workflow-scoped key using scope groups
      - name: payment-service
        scopes:
          - "@payment-workflow"    # Expands to all tags in the group
        description: "Payment processing service"

      # Mixed: scope groups + individual tags + patterns
      - name: finance-team
        scopes:
          - "@payment-workflow"
          - "@reporting-workflow"
          - "finance-*"            # Pattern: matches finance-internal, etc.
        description: "Finance team - payment and reporting access"

      # Individual tags only (no groups)
      - name: external-reporting
        scopes:
          - "public"
          - "reporting"
        description: "External reporting system - limited access"
        expires_at: "2025-12-31T23:59:59Z"

      # Pattern-based
      - name: all-internal
        scopes:
          - "*-internal"           # Matches finance-internal, hr-internal, etc.
        description: "Access to all internal-tagged agents"
```

### Environment Variables

API key values are set via environment variables for security:

```bash
# Key values (never in config file)
AGENTFIELD_API_KEY_ADMIN="sk_admin_xxx"
AGENTFIELD_API_KEY_FINANCE_TEAM="sk_finance_xxx"
AGENTFIELD_API_KEY_EXTERNAL_REPORTING="sk_external_xxx"

# Legacy single key (backwards compatible)
AGENTFIELD_API_KEY="sk_legacy_xxx"
```

### Configuration Loading

```go
// Config structure
type AuthConfig struct {
    // Legacy single key (backwards compatibility)
    APIKey    string      `yaml:"api_key" mapstructure:"api_key"`
    SkipPaths []string    `yaml:"skip_paths" mapstructure:"skip_paths"`

    // Scope groups for workflow-level access
    ScopeGroups map[string]ScopeGroupConfig `yaml:"scope_groups" mapstructure:"scope_groups"`

    // Multiple scoped keys
    Keys      []APIKeyConfig `yaml:"keys" mapstructure:"keys"`
}

type ScopeGroupConfig struct {
    Tags        []string `yaml:"tags"`
    Description string   `yaml:"description,omitempty"`
}

type APIKeyConfig struct {
    Name        string     `yaml:"name"`
    Scopes      []string   `yaml:"scopes"`              // Can include "@group-name"
    Description string     `yaml:"description,omitempty"`
    ExpiresAt   *time.Time `yaml:"expires_at,omitempty"`
}

// Environment variable resolution for key values
func resolveKeyValue(name string) string {
    envKey := "AGENTFIELD_API_KEY_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
    return os.Getenv(envKey)
}

// ExpandScopes resolves @group references to actual tags
func ExpandScopes(scopes []string, groups map[string]ScopeGroupConfig) []string {
    expanded := make([]string, 0)
    for _, scope := range scopes {
        if strings.HasPrefix(scope, "@") {
            groupName := strings.TrimPrefix(scope, "@")
            if group, ok := groups[groupName]; ok {
                expanded = append(expanded, group.Tags...)
            }
        } else {
            expanded = append(expanded, scope)
        }
    }
    return expanded
}
```

---

## Discovery Integration

### Two-Layer Filtering

Discovery uses two sequential filters:

```
GET /api/v1/discovery?tags=["pci"]

Layer 1: Permission Filter (from API key scopes)
┌─────────────────────────────────────────────────────────────────┐
│ API Key: sk_finance (scopes: ["finance", "shared"])             │
│                                                                  │
│ All Agents:                                                      │
│   finance-agent    [finance, pci]      ✓ matches "finance"      │
│   hr-agent         [hr, internal]      ✗ no match               │
│   shared-utils     [shared, pci]       ✓ matches "shared"       │
│   admin-agent      [admin]             ✗ no match               │
│                                                                  │
│ After permission filter: [finance-agent, shared-utils]          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Layer 2: Tag Filter (from request query)
┌─────────────────────────────────────────────────────────────────┐
│ Requested tags: ["pci"]                                          │
│                                                                  │
│ Permitted agents:                                                │
│   finance-agent    [finance, pci]      ✓ has "pci"              │
│   shared-utils     [shared, pci]       ✓ has "pci"              │
│                                                                  │
│ Final result: [finance-agent, shared-utils]                     │
└─────────────────────────────────────────────────────────────────┘
```

### Discovery Handler Changes

```go
func (h *DiscoveryHandler) DiscoverCapabilities(c *gin.Context) {
    scopes := getKeyScopes(c)
    filters := parseDiscoveryFilters(c)

    // Get all agents
    agents, err := h.storage.ListAgents(ctx, AgentFilters{})

    // Layer 1: Filter by permission (key scopes)
    permitted := h.filterByPermission(agents, scopes)

    // Layer 2: Filter by requested tags
    if len(filters.Tags) > 0 {
        permitted = h.filterByTags(permitted, filters.Tags)
    }

    // Apply other filters (health status, patterns, etc.)
    result := h.applyFilters(permitted, filters)

    c.JSON(http.StatusOK, DiscoveryResponse{Capabilities: result})
}
```

### Memory Endpoint Protection

Memory operations are protected by the same tag-based access control:

| Scope | Protection Behavior |
|-------|---------------------|
| `global` | Super keys only (sensitive shared state) |
| `workflow` | Key must have access to the workflow's initiating agent |
| `session` | Key must have access to the session's initiating agent |
| `actor` | Key must have access to the actor's associated agent |

**Example:** A key with `scopes: ["finance"]` can read/write memory in workflows initiated by agents tagged `finance`, but cannot access memory from `hr`-tagged workflows.

**Implementation note:** The workflow/session metadata stores the initiating agent's tags at creation time for permission lookups.

---

## SDK Changes

All three SDKs (Python, Go, TypeScript) require internal updates to support key propagation. **These are transparent changes with no breaking API modifications.**

### What SDKs Must Do

1. **Capture incoming key context** — When receiving a request from the control plane, extract the propagation headers
2. **Store in request context** — Make available for the duration of the request handling
3. **Forward on outbound calls** — When calling `agent.call()` or equivalent, include the captured headers

### SDK Change Scope

| SDK | Files Affected | Change Type |
|-----|----------------|-------------|
| Python | `agent.py`, `client.py` | Internal - header handling |
| Go | `agent/agent.go`, `client/client.go` | Internal - header handling |
| TypeScript | `Agent.ts`, `AgentFieldClient.ts` | Internal - header handling |

**No public API changes required.** Developers continue to use `agent.call("target.reasoner", input)` as before.

---

## REST API Specification

### Authentication

All requests include API key via header or query param:

```http
# Header (preferred)
X-API-Key: sk_finance_xxx

# Bearer token
Authorization: Bearer sk_finance_xxx

# Query param (for SSE/WebSocket)
GET /api/v1/events?api_key=sk_finance_xxx
```

### Error Responses

#### 401 Unauthorized - Invalid or Missing Key

```json
{
  "error": "unauthorized",
  "message": "invalid or missing API key"
}
```

#### 403 Forbidden - Key Lacks Permission

```json
{
  "error": "access_denied",
  "message": "API key does not have access to this agent",
  "agent": "admin-agent",
  "hint": "Agent requires one of these tags: admin"
}
```

### Admin Endpoints (Super Key Required)

```yaml
# List all API keys (metadata only, no secrets)
GET /api/v1/admin/keys
Authorization: Bearer sk_admin_xxx

Response: 200 OK
{
  "keys": [
    {
      "id": "key_abc123",
      "name": "finance-team",
      "scopes": ["finance", "shared"],
      "description": "Finance team key",
      "enabled": true,
      "created_at": "2025-01-15T10:00:00Z",
      "last_used_at": "2025-01-20T14:30:00Z"
    }
  ]
}

# Check access for a key (for debugging)
POST /api/v1/admin/keys/check-access
Authorization: Bearer sk_admin_xxx
Content-Type: application/json

{
  "key_name": "finance-team",
  "target_agent": "payment-processor"
}

Response: 200 OK
{
  "allowed": true,
  "key_scopes": ["finance", "shared"],
  "agent_tags": ["finance", "pci"],
  "matched_on": "finance"
}

# Get access audit log
GET /api/v1/admin/access-log?limit=100&allowed=false
Authorization: Bearer sk_admin_xxx

Response: 200 OK
{
  "entries": [
    {
      "timestamp": "2025-01-20T14:30:00Z",
      "api_key_name": "external-reporting",
      "target_agent": "admin-agent",
      "allowed": false,
      "deny_reason": "no matching tags"
    }
  ]
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Key leakage | Keys stored as bcrypt hashes; values only in env vars |
| Scope escalation | Agents can only opt-in via their own tags; cannot grant access to others |
| Header forgery | Propagated key context is HMAC-signed; agents cannot forge elevated permissions |
| Replay attacks | Signed headers include timestamp; rejected if > 5 minutes old |
| Enumeration via discovery | Discovery filtered by permissions first |
| Expired key usage | Expiration checked on every request |
| Internal call bypass | Permission check at every hop, not just entry point |

### Key Storage Security

```go
// Keys are hashed before storage
func hashKey(plainKey string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(plainKey), bcrypt.DefaultCost)
    return string(hash), err
}

// Verification
func verifyKey(plainKey, hash string) bool {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainKey)) == nil
}
```

### Audit Trail

All access decisions can optionally be logged:

```go
type AccessAuditEntry struct {
    Timestamp     time.Time `json:"timestamp"`
    APIKeyID      string    `json:"api_key_id"`
    APIKeyName    string    `json:"api_key_name"`
    TargetAgent   string    `json:"target_agent"`
    TargetReasoner string   `json:"target_reasoner,omitempty"`
    AgentTags     []string  `json:"agent_tags"`
    KeyScopes     []string  `json:"key_scopes"`
    Allowed       bool      `json:"allowed"`
    DenyReason    string    `json:"deny_reason,omitempty"`
}
```

---

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1)

**Deliverables:**
- [ ] `APIKey` type and storage interface
- [ ] Config loading for multiple keys
- [ ] Environment variable resolution for key values
- [ ] Key hashing and verification
- [ ] Database migration for `api_keys` table

**Files:**
- `control-plane/pkg/types/api_key.go` (new)
- `control-plane/internal/config/config.go` (modify)
- `control-plane/internal/storage/api_keys.go` (new)
- `control-plane/migrations/018_create_api_keys.sql` (new)

### Phase 2: Auth Middleware (Week 1-2)

**Deliverables:**
- [ ] Multi-key auth middleware
- [ ] Scope resolution and context attachment
- [ ] Backwards compatibility with legacy single key
- [ ] Key expiration checking

**Files:**
- `control-plane/internal/server/middleware/auth.go` (modify)
- `control-plane/internal/server/middleware/scopes.go` (new)

### Phase 3: Enforcement (Week 2)

**Deliverables:**
- [ ] Tag matching algorithm with wildcards
- [ ] Execute handler permission check
- [ ] Discovery handler permission filter
- [ ] Memory handler permission check
- [ ] Internal call bypass logic

**Files:**
- `control-plane/internal/handlers/execute.go` (modify)
- `control-plane/internal/handlers/discovery.go` (modify)
- `control-plane/internal/handlers/memory.go` (modify)
- `control-plane/internal/services/access_control.go` (new)

### Phase 4: Admin API & Audit (Week 3)

**Deliverables:**
- [ ] Admin endpoints for key management
- [ ] Access check debugging endpoint
- [ ] Audit logging (optional, configurable)
- [ ] Migration for audit log table

**Files:**
- `control-plane/internal/handlers/admin/keys.go` (new)
- `control-plane/internal/server/routes.go` (modify)
- `control-plane/migrations/019_create_access_audit_log.sql` (new)

### Phase 5: Testing & Documentation (Week 3-4)

**Deliverables:**
- [ ] Unit tests for tag matching
- [ ] Integration tests for permission enforcement
- [ ] Update API documentation
- [ ] Configuration guide

---

## Success Metrics

### Functional Metrics

- [ ] Super keys maintain full access (backwards compatible)
- [ ] Scoped keys can only access permitted agents
- [ ] Discovery returns only permitted agents
- [ ] Wildcard patterns work correctly (`finance*`)
- [ ] Internal agent-to-agent calls are not blocked

### Performance Metrics

- Key lookup: < 1ms (cached)
- Permission check: < 0.5ms
- No measurable latency increase for super keys

### Operational Metrics

- Configuration errors logged clearly at startup
- Access denials include actionable hints
- Audit log captures all denials (if enabled)

---

## Appendix A: Configuration Examples

### Single-Team Deployment

```yaml
api:
  auth:
    keys:
      - name: team
        scopes: ["*"]
        description: "Single team - full access"
```

### Workflow-Based Access (Recommended)

```yaml
api:
  auth:
    scope_groups:
      # Define workflows as scope groups
      order-processing:
        tags: ["orders", "inventory", "payment", "shipping", "notification"]
        description: "Complete order processing workflow"

      customer-service:
        tags: ["customers", "orders", "support", "crm", "notification"]
        description: "Customer service operations"

      analytics:
        tags: ["reporting", "analytics", "customers", "orders"]
        description: "Read-only analytics access"

    keys:
      - name: admin
        scopes: ["*"]

      - name: order-service
        scopes: ["@order-processing"]
        description: "Order processing microservice"

      - name: support-team
        scopes: ["@customer-service"]
        description: "Customer support team"

      - name: analytics-dashboard
        scopes: ["@analytics"]
        description: "Analytics dashboard - read-only"
```

### Multi-Tenant Deployment

```yaml
api:
  auth:
    scope_groups:
      # Each tenant gets their own scope group
      tenant-acme-workflows:
        tags: ["tenant-acme", "tenant-acme-*", "shared"]

      tenant-globex-workflows:
        tags: ["tenant-globex", "tenant-globex-*", "shared"]

    keys:
      - name: admin
        scopes: ["*"]
        description: "Platform admin"

      - name: tenant-acme
        scopes: ["@tenant-acme-workflows"]
        description: "ACME Corp tenant"

      - name: tenant-globex
        scopes: ["@tenant-globex-workflows"]
        description: "Globex tenant"
```

### Department-Based Access

```yaml
api:
  auth:
    scope_groups:
      finance-workflows:
        tags: ["finance", "finance-*", "audit", "billing", "reporting", "shared"]

      hr-workflows:
        tags: ["hr", "hr-*", "employees", "payroll", "shared"]

      engineering-workflows:
        tags: ["eng-*", "ci-cd", "monitoring", "shared", "dev-*"]

    keys:
      - name: admin
        scopes: ["*"]

      - name: finance-team
        scopes: ["@finance-workflows"]

      - name: hr-team
        scopes: ["@hr-workflows"]

      - name: engineering
        scopes: ["@engineering-workflows"]
```

### External Integration

```yaml
api:
  auth:
    scope_groups:
      public-api:
        tags: ["public", "readonly"]
        description: "Public API access"

    keys:
      - name: admin
        scopes: ["*"]

      - name: external-crm
        scopes: ["@public-api", "crm-sync"]
        description: "CRM integration - limited access"
        expires_at: "2025-06-30T23:59:59Z"

      - name: webhook-receiver
        scopes: ["public", "webhooks"]
        description: "Inbound webhooks only"
```

---

## Appendix B: Agent Tag Examples

### Python SDK

```python
from agentfield import Agent

# Agent-level tags apply to all reasoners
app = Agent(
    node_id="payment-processor",
    tags=["finance", "pci-compliant"]
)

# Reasoner-specific tags (additive)
@app.reasoner(tags=["high-value"])
async def process_payment(amount: float) -> dict:
    # This reasoner has tags: ["finance", "pci-compliant", "high-value"]
    return {"processed": True}

@app.reasoner(tags=["reporting"])
async def get_daily_totals() -> dict:
    # This reasoner has tags: ["finance", "pci-compliant", "reporting"]
    return {"total": 50000}
```

### Go SDK

```go
agent := agentfield.NewAgent(agentfield.Config{
    NodeID: "payment-processor",
    Tags:   []string{"finance", "pci-compliant"},
})

agent.RegisterReasoner("process_payment", agentfield.ReasonerConfig{
    Tags: []string{"high-value"},
}, processPaymentHandler)
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Tag** | A string label self-assigned by an agent to opt-in to access |
| **Scope** | A tag pattern on an API key defining what it can access |
| **Scope group** | A named collection of tags (e.g., `@payment-workflow`) for workflow-level access |
| **Super key** | An API key with `scopes: ["*"]` that can access everything |
| **Scoped key** | An API key with specific scopes limiting its access |
| **Permission check** | Verifying that key scopes intersect with agent tags |
| **Key propagation** | Passing the API key context through the workflow so every hop is authorized |
| **Consent** | An agent opting-in to access by assigning itself a tag |

---

*End of PRD*
