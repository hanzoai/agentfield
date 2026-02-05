# VC-Based Authorization Architecture

**Version:** 1.1
**Status:** Implementation
**Date:** February 2026

---

## Executive Summary

This document describes the Verifiable Credential (VC) based authorization system for AgentField. This system provides a self-service permission request and admin approval workflow for controlling inter-agent communication.

**Key Principles:**
- Agents self-assign tags (identity only, no approval needed)
- Protected agents are defined via config file (pattern-based rules)
- Agents declare dependencies at registration → creates permission requests proactively
- Calling protected agents requires admin approval via UI
- Admin can revoke permissions at any time
- Control plane issues signed PermissionVCs upon approval
- `did:web` enables real-time revocation
- Control plane is source of truth; nodes cache VCs in memory

---

## System Overview

### Flow 1: Registration with Dependencies

When an agent registers, it declares the tags of agents it intends to call. This creates permission requests proactively, before the first call attempt.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     REGISTRATION WITH DEPENDENCIES                          │
└─────────────────────────────────────────────────────────────────────────────┘

  AGENT A                     CONTROL PLANE                         ADMIN
  (caller)
     │                              │                                  │
     │  1. Register                 │                                  │
     │  ─────────────────────────►  │                                  │
     │  {                           │                                  │
     │    tags: ["marketing"],      │   (agent's own identity)        │
     │    dependencies: ["admin",   │   (tags A intends to call)      │
     │                   "finance"] │                                  │
     │  }                           │                                  │
     │                              │                                  │
     │                              │  2. Check each dependency:       │
     │                              │     - "admin" → protected?  YES  │
     │                              │     - "finance" → protected? YES │
     │                              │                                  │
     │                              │  3. Create pending requests      │
     │                              │     for each protected tag       │
     │                              │                                  │
     │  4. Receives did:web         │                                  │
     │  ◄─────────────────────────  │                                  │
     │  + warning: 2 permissions    │                                  │
     │    pending                   │                                  │
     │                              │                                  │
     │                              │  5. Show in Admin UI             │
     │                              │  ─────────────────────────────►  │
     │                              │  "agent-a needs: admin, finance" │
     │                              │                                  │
     │                              │                   6. Bulk review │
     │                              │                   [Approve all]  │
     │                              │  ◄─────────────────────────────  │
```

**Note:** The agent's own tags (`tags: ["marketing"]`) are stored for reference but don't trigger any special processing. They help admins understand what kind of agent is requesting access.

### Flow 2: Runtime Permission Check

When an agent calls another agent at runtime, the control plane checks permissions. If no approval exists, it creates a request and rejects the call.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RUNTIME PERMISSION CHECK                             │
└─────────────────────────────────────────────────────────────────────────────┘

  AGENT A                     CONTROL PLANE                         ADMIN
  (caller)
     │                              │                                  │
     │  1. Call Agent B             │                                  │
     │     (protected agent)        │                                  │
     │  ─────────────────────────►  │                                  │
     │                              │                                  │
     │                              │  2. Is B protected?              │
     │                              │     YES (tag: "admin")           │
     │                              │                                  │
     │                              │  3. Has A→B approval?            │
     │                              │                                  │
     ├──────────────────────────────┼──────────────────────────────────┤
     │           IF NO APPROVAL     │                                  │
     ├──────────────────────────────┼──────────────────────────────────┤
     │                              │                                  │
     │                              │  4. Create pending request       │
     │                              │     (if not exists)              │
     │                              │                                  │
     │  5. Error: Permission        │                                  │
     │     required, request        │                                  │
     │     pending                  │                                  │
     │  ◄─────────────────────────  │                                  │
     │                              │                                  │
     │                              │  6. Show in Admin UI             │
     │                              │  ─────────────────────────────►  │
     │                              │                                  │
     ├──────────────────────────────┼──────────────────────────────────┤
     │          IF APPROVED         │                                  │
     ├──────────────────────────────┼──────────────────────────────────┤
     │                              │                                  │
     │                              │  4. Approval valid               │
     │                              │     (not expired, not revoked)   │
     │                              │                                  │
     │  5. Call proceeds            │                                  │
     │  ◄─────────────────────────  │                                  │
     │                              │                                  │
```

### Flow 3: Revocation

Admin can revoke permissions at any time. Next call will fail.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              REVOCATION                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  AGENT A                     CONTROL PLANE                         ADMIN
     │                              │                                  │
     │                              │             1. Revoke A→B        │
     │                              │  ◄─────────────────────────────  │
     │                              │                                  │
     │                              │  2. Mark approval as "revoked"   │
     │                              │     Set revoked_at timestamp     │
     │                              │                                  │
     │  3. Call Agent B             │                                  │
     │  ─────────────────────────►  │                                  │
     │                              │                                  │
     │                              │  4. Check approval → REVOKED     │
     │                              │                                  │
     │  5. Error: Permission        │                                  │
     │     revoked                  │                                  │
     │  ◄─────────────────────────  │                                  │
```

---

## Core Concepts

### 1. Agent Identity (Tags)

Agents declare their identity through self-assigned tags. **No approval is needed for tag assignment.** Tags are informational only - they help admins understand what kind of agent is requesting access.

```python
# Python SDK
app = Agent(
    node_id="finance-bot",
    tags=["finance", "reporting"]  # Self-declared identity (informational)
)

@app.skill(tags=["pci-compliant"])  # Additional skill-level tags
def process_payment():
    ...
```

Tags serve as:
- **Identity declaration** - "I am a finance agent"
- **Capability advertisement** - "I handle PCI-compliant operations"
- **Discovery metadata** - Other agents can find me by tags
- **Admin context** - Helps admin decide whether to approve permission requests

**Important:** The system does NOT auto-enforce based on caller tags. Tags don't grant or restrict permissions - they're purely informational for admin review.

### 2. Dependency Declaration

Agents declare the tags of agents they intend to call at registration. This creates permission requests proactively.

```python
# Python SDK
app = Agent(
    node_id="reporting-bot",
    tags=["reporting"],           # My identity
    dependencies=["finance", "admin"]  # Tags I need to call
)
```

When `reporting-bot` registers:
1. Control plane checks if `finance` or `admin` are protected tags
2. For each protected tag, creates a pending permission request
3. Admin can pre-approve before the agent even tries to call

This enables:
- **Proactive approval** - Requests created before first call
- **Bulk approval** - Admin can approve multiple dependencies at once
- **Visibility** - See all required permissions for an agent upfront

### 3. Protected Agents

Protected agents are defined via **config file**. These rules determine which agents require permission to call.

```yaml
# agentfield.yaml
permissions:
  enabled: true
  protected_agents:
    # By exact tag
    - pattern_type: tag
      pattern: admin
      description: "Agents with admin tag require permission"

    # By tag pattern (wildcard)
    - pattern_type: tag_pattern
      pattern: "finance*"
      description: "All finance-related agents require permission"

    # By specific agent ID
    - pattern_type: agent_id
      pattern: "payment-gateway"
      description: "Specific agent requires permission"
```

Rules can also be added via Admin UI (stored in database), but config file is the primary source.

**Pattern Types:**
| Type | Example | Matches |
|------|---------|---------|
| `tag` | `admin` | Agents with exact tag "admin" |
| `tag_pattern` | `finance*` | Agents with tags starting with "finance" |
| `agent_id` | `payment-gateway` | Specific agent by ID |

### 4. Permission Approval

When Agent A tries to call protected Agent B:

1. Control plane checks if B matches any protected agent rule
2. If protected, checks if approval exists for (A's DID, B's DID)
3. If no approval, creates pending request and returns error
4. Admin sees request in UI and can approve/reject
5. Upon approval, control plane stores approval record
6. Future calls from A to B succeed (same DID pair)

**Revocation:** Admin can revoke permissions at any time. When revoked:
- The approval status changes to "revoked"
- A `revoked_at` timestamp is recorded
- All subsequent calls are rejected
- Agent must request permission again (new approval needed)

### 5. Verifiable Credentials (VCs)

Upon approval, the system can issue a PermissionVC - a cryptographically signed proof of the approval:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "PermissionCredential"],
  "issuer": "did:web:agentfield.example.com",
  "issuanceDate": "2026-02-04T12:00:00Z",
  "expirationDate": "2026-03-06T12:00:00Z",
  "credentialSubject": {
    "caller": "did:web:agentfield.example.com:agents:agent-a",
    "target": "did:web:agentfield.example.com:agents:agent-b",
    "permission": "call"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-04T12:00:00Z",
    "verificationMethod": "did:web:agentfield.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXQjecWufY46..."
  }
}
```

### 6. DID Methods

#### did:key (Current - Limited)
- DID derived from public key: `did:key:z6MkpTHR8VNs...`
- Self-contained, no external resolution
- **Cannot be revoked** - only time-based expiry

#### did:web (New - Full Support)
- DID resolves to URL: `did:web:agentfield.example.com:agents:agent-a`
- Control plane hosts DID document at that URL
- **Real-time revocation** - return 404 or revoked status
- Verifiers fetch fresh public key on each verification

---

## Trust Model

### What We Trust

| Entity | Trust Level | Rationale |
|--------|-------------|-----------|
| Control Plane | Full | Central authority, hosts DIDs, issues VCs |
| Admin | Full | Makes approval decisions |
| Agent's Private Key | Cryptographic | Proves DID ownership via signatures |

### What We Don't Trust

| Entity | Protection Mechanism |
|--------|---------------------|
| Developers claiming tags | Tags are identity only, not permissions |
| Agents spoofing DIDs | DID ownership proven via cryptographic signature |
| Forged VCs | VC signature verified against issuer's public key |
| Expired approvals | Expiration checked on each call |

### Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  SECURITY BOUNDARY: Control Plane                               │
│                                                                 │
│  - Issues DIDs (did:web)                                       │
│  - Hosts DID documents (enables revocation)                    │
│  - Stores approval records (source of truth)                   │
│  - Issues PermissionVCs (signed credentials)                   │
│  - Enforces permission checks on execution                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Approval required
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: Admin Approval                                 │
│                                                                 │
│  - Reviews permission requests                                  │
│  - Approves/rejects with duration                              │
│  - Can revoke at any time                                      │
│  - Configures protected agent rules                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Credentials issued
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT BOUNDARY: Self-Declared Identity                         │
│                                                                 │
│  - Agents assign their own tags (informational, no approval)   │
│  - Tags = identity, NOT permissions                            │
│  - Agents declare dependencies (tags they intend to call)      │
│  - Agents cannot grant themselves access to protected agents   │
│  - Must request and wait for admin approval                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Contracts

### Agent Registration (with Dependencies)

When an agent registers, it can declare dependencies - tags of agents it intends to call.

```http
POST /api/v1/agents/register
Content-Type: application/json

{
  "agent_id": "reporting-bot",
  "tags": ["reporting", "analytics"],     // Agent's own identity (informational)
  "dependencies": ["finance", "admin"]    // Tags this agent needs to call
}

Response 200:
{
  "agent_id": "reporting-bot",
  "did": "did:web:example.com:agents:reporting-bot",
  "tags": ["reporting", "analytics"],
  "pending_permissions": [
    {
      "target_tag": "finance",
      "status": "pending",
      "request_id": 124
    },
    {
      "target_tag": "admin",
      "status": "pending",
      "request_id": 125
    }
  ]
}
```

The control plane:
1. Creates a did:web for the agent
2. Stores agent's tags (informational)
3. For each dependency that matches a protected agent rule, creates a pending permission request
4. Returns list of pending permissions so agent knows what's awaiting approval

### Permission Request Flow

#### Request Permission (Manual)
```http
POST /api/v1/permissions/request
Content-Type: application/json

{
  "caller_did": "did:web:example.com:agents:agent-a",
  "target_did": "did:web:example.com:agents:agent-b",
  "reason": "Need to access admin functions"
}

Response 201:
{
  "id": 123,
  "status": "pending",
  "created_at": "2026-02-04T12:00:00Z"
}
```

#### Check Permission
```http
GET /api/v1/permissions/check?caller_did=...&target_did=...

Response 200 (approved):
{
  "requires_permission": true,
  "has_valid_approval": true,
  "approval_status": "approved",
  "expires_at": "2026-03-06T12:00:00Z",
  "vc": "eyJhbGciOiJFZDI1NTE5..."
}

Response 200 (pending):
{
  "requires_permission": true,
  "has_valid_approval": false,
  "approval_status": "pending"
}

Response 200 (not protected):
{
  "requires_permission": false,
  "has_valid_approval": true
}
```

### Admin Endpoints

#### List Pending Requests
```http
GET /api/v1/admin/permissions/pending

Response 200:
{
  "requests": [
    {
      "id": 123,
      "caller_did": "did:web:example.com:agents:agent-a",
      "caller_agent_id": "agent-a",
      "target_did": "did:web:example.com:agents:agent-b",
      "target_agent_id": "agent-b",
      "status": "pending",
      "created_at": "2026-02-04T12:00:00Z"
    }
  ]
}
```

#### Approve Permission
```http
POST /api/v1/admin/permissions/123/approve
Content-Type: application/json

{
  "duration_hours": 720,  // 30 days, null = permanent
  "reason": "Approved for Q1 project"
}

Response 200:
{
  "id": 123,
  "status": "approved",
  "approved_by": "admin",
  "approved_at": "2026-02-04T12:00:00Z",
  "expires_at": "2026-03-06T12:00:00Z"
}
```

#### Revoke Permission
```http
POST /api/v1/admin/permissions/123/revoke
Content-Type: application/json

{
  "reason": "Access no longer needed"
}

Response 200:
{
  "id": 123,
  "status": "revoked",
  "revoked_at": "2026-02-04T12:00:00Z"
}
```

### DID Resolution (did:web)

```http
GET /agents/agent-a/did.json

Response 200 (active):
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com:agents:agent-a",
  "verificationMethod": [{
    "id": "did:web:example.com:agents:agent-a#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:example.com:agents:agent-a",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "..."
    }
  }],
  "authentication": ["did:web:example.com:agents:agent-a#key-1"]
}

Response 404 (revoked):
{
  "error": "did_revoked",
  "message": "This DID has been revoked"
}
```

---

## Configuration

### What Goes Where

| Data | Source | Purpose |
|------|--------|---------|
| **Protected agent rules** | Config file (primary) | Defines which agents require permission |
| **Protected agent rules** | Database (secondary) | Rules added via Admin UI |
| **Permission approvals** | Database | Tracks caller→target approval status |
| **DID documents** | Database | Stores did:web documents for resolution |
| **Agent tags** | Agent registration | Self-declared identity (informational) |
| **Agent dependencies** | Agent registration | Tags the agent intends to call |

### Full Configuration Example

```yaml
# agentfield.yaml

permissions:
  # Enable/disable the permission system
  enabled: true

  # Domain for did:web DIDs
  did_web_domain: "agentfield.example.com"

  # Default approval duration (hours), null = permanent
  default_duration_hours: 720  # 30 days

  # Auto-request permission when call is denied
  auto_request_on_deny: true

  # Protected agent rules
  protected_agents:
    # By tag (exact match)
    - pattern_type: tag
      pattern: admin
      description: "Admin-tagged agents require permission"

    # By tag pattern (wildcard)
    - pattern_type: tag_pattern
      pattern: "finance*"
      description: "Finance agents require permission"

    # By agent ID (specific agent)
    - pattern_type: agent_id
      pattern: "payment-gateway"
      description: "Payment gateway requires permission"
```

### Environment Variables

```bash
# Enable permissions
AGENTFIELD_PERMISSIONS_ENABLED=true

# did:web domain
AGENTFIELD_PERMISSIONS_DID_WEB_DOMAIN=agentfield.example.com

# Default duration
AGENTFIELD_PERMISSIONS_DEFAULT_DURATION_HOURS=720
```

---

## Database Schema

### permission_approvals
```sql
CREATE TABLE permission_approvals (
    id              BIGSERIAL PRIMARY KEY,
    caller_did      TEXT NOT NULL,
    target_did      TEXT NOT NULL,
    caller_agent_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    approved_by     TEXT,
    approved_at     TIMESTAMP WITH TIME ZONE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    expires_at      TIMESTAMP WITH TIME ZONE,
    reason          TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_caller_target UNIQUE (caller_did, target_did)
);
```

### did_documents
```sql
CREATE TABLE did_documents (
    did             TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    did_document    JSONB NOT NULL,
    public_key_jwk  TEXT NOT NULL,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

### protected_agents_config
```sql
CREATE TABLE protected_agents_config (
    id              BIGSERIAL PRIMARY KEY,
    pattern_type    TEXT NOT NULL,
    pattern         TEXT NOT NULL,
    description     TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_pattern UNIQUE (pattern_type, pattern)
);
```

---

## Backward Compatibility

### API Keys Continue to Work

The VC authorization system is **additive**. Existing API key authentication continues to function:

- Requests with valid API keys are authenticated as before
- Super keys (`scopes: ["*"]`) bypass permission checks entirely
- Scoped keys still enforce tag-based access control

### Migration Path

1. **Phase 1:** Deploy with `permissions.enabled: false` (default)
2. **Phase 2:** Enable permissions, configure protected agents
3. **Phase 3:** Monitor permission requests, train admins on approval workflow
4. **Phase 4:** Gradually expand protected agent rules

### Coexistence Rules

| Scenario | Behavior |
|----------|----------|
| Super API key + protected agent | Allowed (super key bypasses) |
| Scoped API key + protected agent | Permission check required |
| No API key + protected agent | Permission check required |
| Any key + unprotected agent | Normal access control |

---

## Appendix: Glossary

| Term | Definition |
|------|------------|
| **DID** | Decentralized Identifier - globally unique identifier for agents |
| **did:key** | DID method where identifier is derived from public key |
| **did:web** | DID method where identifier resolves to a web URL |
| **VC** | Verifiable Credential - signed, tamper-evident credential |
| **PermissionVC** | VC that proves permission to call a protected agent |
| **Protected Agent** | Agent that requires explicit permission to call |
| **Approval** | Admin decision granting permission for a caller-target pair |
| **Revocation** | Invalidating a DID or permission before expiration |

---

*End of Architecture Document*
