# VC-Based Authorization Architecture

**Version:** 1.0
**Status:** Implementation
**Date:** February 2026

---

## Executive Summary

This document describes the Verifiable Credential (VC) based authorization system for AgentField. This system replaces the traditional API key distribution model with a self-service permission request and admin approval workflow.

**Key Principles:**
- Agents self-assign tags (identity declaration, no approval needed)
- Calling protected agents requires admin approval via UI
- Control plane issues signed PermissionVCs upon approval
- `did:web` enables real-time revocation
- Control plane is source of truth; nodes cache VCs in memory

---

## System Overview

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VC AUTHORIZATION FLOW                             │
└─────────────────────────────────────────────────────────────────────────────┘

  AGENT A                     CONTROL PLANE                         ADMIN
  (caller)
     │                              │                                  │
     │  1. Register with tags       │                                  │
     │  ─────────────────────────►  │                                  │
     │  tags: ["marketing"]         │                                  │
     │                              │                                  │
     │  2. Receives did:web         │                                  │
     │  ◄─────────────────────────  │                                  │
     │  did:web:example.com:        │                                  │
     │    agents:agent-a            │                                  │
     │                              │                                  │
     │  3. Try to call Agent B      │                                  │
     │     (protected agent)        │                                  │
     │  ─────────────────────────►  │                                  │
     │                              │                                  │
     │                              │  4. Check: Is B protected?       │
     │                              │     YES (tag: "admin")           │
     │                              │                                  │
     │                              │  5. Check: Has approval?         │
     │                              │     NO                           │
     │                              │                                  │
     │                              │  6. Auto-create request          │
     │                              │                                  │
     │  7. Error: Permission        │                                  │
     │     required                 │                                  │
     │  ◄─────────────────────────  │                                  │
     │                              │                                  │
     │                              │  8. Show in Admin UI             │
     │                              │  ─────────────────────────────►  │
     │                              │  "agent-a wants to call agent-b" │
     │                              │                                  │
     │                              │                        9. Review │
     │                              │                   [Approve 30d]  │
     │                              │  ◄─────────────────────────────  │
     │                              │                                  │
     │                              │  10. Store approval              │
     │                              │      Issue PermissionVC          │
     │                              │                                  │
     │  11. Retry call to B         │                                  │
     │  ─────────────────────────►  │                                  │
     │                              │                                  │
     │                              │  12. Check: Has approval?        │
     │                              │      YES - return VC             │
     │                              │                                  │
     │  13. Call succeeds           │                                  │
     │  ◄─────────────────────────  │                                  │
```

---

## Core Concepts

### 1. Agent Identity (Tags)

Agents declare their identity through self-assigned tags. **No approval is needed for tag assignment.**

```python
# Python SDK
app = Agent(
    node_id="finance-bot",
    tags=["finance", "reporting"]  # Self-declared identity
)

@app.skill(tags=["pci-compliant"])  # Additional skill-level tags
def process_payment():
    ...
```

Tags serve as:
- **Identity declaration** - "I am a finance agent"
- **Capability advertisement** - "I handle PCI-compliant operations"
- **Discovery metadata** - Other agents can find me by tags

### 2. Protected Agents

Admins configure which agents require permission to call via pattern rules:

```yaml
permissions:
  protected_agents:
    - pattern_type: tag
      pattern: admin
      description: "Agents with admin tag require permission"

    - pattern_type: tag_pattern
      pattern: "finance*"
      description: "All finance-related agents require permission"

    - pattern_type: agent_id
      pattern: "payment-gateway"
      description: "Specific agent requires permission"
```

### 3. Permission Approval

When Agent A tries to call protected Agent B:

1. Control plane checks if B matches any protected agent rule
2. If protected, checks if approval exists for (A's DID, B's DID)
3. If no approval, creates pending request and returns error
4. Admin sees request in UI and can approve/reject
5. Upon approval, control plane stores approval record
6. Future calls from A to B succeed (same DID pair)

### 4. Verifiable Credentials (VCs)

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

### 5. DID Methods

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
│  - Agents assign their own tags (no approval)                  │
│  - Tags = identity, NOT permissions                            │
│  - Agents cannot grant themselves access to protected agents   │
│  - Must request and wait for admin approval                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Contracts

### Permission Request Flow

#### Request Permission
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
