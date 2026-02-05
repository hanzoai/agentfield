# DID Authentication Security Model

**Version:** 1.0
**Status:** Implementation Required
**Date:** February 2026

---

## The Problem

Currently, agents claim their DID via HTTP header (`X-Caller-DID`), but this is **not cryptographically verified**. A malicious agent could:

```
# Malicious agent claims to be agent-a
curl -X POST http://control-plane/execute \
  -H "X-Caller-DID: did:web:example.com:agents:agent-a" \
  -d '{"target": "protected-agent"}'
```

If `agent-a` has permission to call `protected-agent`, the malicious agent bypasses security.

---

## The Solution: Cryptographic DID Authentication

Every request claiming a DID must be **signed** with the private key corresponding to that DID. The control plane **verifies** the signature against the DID document's public key.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DID AUTHENTICATION FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘

  AGENT A                                    CONTROL PLANE
     │                                              │
     │  1. Build request payload                    │
     │     {target: "agent-b", input: {...}}       │
     │                                              │
     │  2. Create signature payload                 │
     │     timestamp + request_hash                 │
     │                                              │
     │  3. Sign with private key                    │
     │     signature = Ed25519.sign(payload, key)   │
     │                                              │
     │  4. Send request with signature              │
     │  ─────────────────────────────────────────►  │
     │  Headers:                                    │
     │    X-Caller-DID: did:web:...:agent-a        │
     │    X-DID-Signature: base64(signature)        │
     │    X-DID-Timestamp: 1707000000               │
     │                                              │
     │                                              │  5. Extract claimed DID
     │                                              │
     │                                              │  6. Resolve DID → get public key
     │                                              │     GET /agents/agent-a/did.json
     │                                              │
     │                                              │  7. Verify signature
     │                                              │     Ed25519.verify(payload, sig, pubkey)
     │                                              │
     │                                              │  8. Check timestamp (prevent replay)
     │                                              │     |now - timestamp| < 5 minutes
     │                                              │
     │                                              │  9. If valid, proceed with permission check
     │                                              │
     │  10. Response                                │
     │  ◄─────────────────────────────────────────  │
```

---

## Key Distribution Model

### Option A: Control Plane Holds All Keys (Current)

```
Control Plane
├── Master Seed (secret)
└── Derives keys for each agent using path: m/44'/web'/{agentID}'

When agent registers:
1. Control plane generates did:web + key pair
2. Control plane stores public key in DID document
3. Control plane returns private key to agent (one time)
4. Agent stores private key securely
```

**Pros:** Deterministic, can regenerate keys if needed
**Cons:** Private key transmitted over network once

### Option B: Agent Generates Own Keys

```
Agent
├── Generates Ed25519 key pair locally
└── Sends public key to control plane

When agent registers:
1. Agent generates key pair locally
2. Agent sends public key to control plane
3. Control plane stores in DID document
4. Agent keeps private key (never transmitted)
```

**Pros:** Private key never leaves agent
**Cons:** Cannot recover if agent loses key

### Recommendation: Option A with Secure Delivery

For simplicity, use Option A but ensure:
- Private key returned only once at registration
- Transmitted over HTTPS
- Agent must store securely (env var, secret manager)

---

## Implementation Requirements

### 1. Registration Response Must Include Private Key

```go
// DID registration response
type DIDRegistrationResponse struct {
    DID           string `json:"did"`
    PublicKeyJWK  string `json:"public_key_jwk"`
    PrivateKeyJWK string `json:"private_key_jwk"`  // NEW: One-time delivery
}
```

### 2. SDK Must Store and Use Private Key

```python
# Python SDK - Agent initialization
class Agent:
    def __init__(self, node_id: str, private_key: str = None):
        self.node_id = node_id
        self.private_key = private_key or os.environ.get("AGENTFIELD_PRIVATE_KEY")

    async def call(self, target: str, input: dict) -> dict:
        # Build signature
        timestamp = int(time.time())
        payload = f"{timestamp}:{hash(input)}"
        signature = self._sign(payload)

        # Make request with signature
        response = await self.http_client.post(
            f"{self.server}/execute",
            headers={
                "X-Caller-DID": self.did,
                "X-DID-Signature": base64.b64encode(signature),
                "X-DID-Timestamp": str(timestamp),
            },
            json={"target": target, "input": input}
        )
```

### 3. Control Plane Must Verify Signatures

```go
// Middleware: DID Authentication
func DIDAuthMiddleware(didWebService *DIDWebService) gin.HandlerFunc {
    return func(c *gin.Context) {
        callerDID := c.GetHeader("X-Caller-DID")
        signature := c.GetHeader("X-DID-Signature")
        timestamp := c.GetHeader("X-DID-Timestamp")

        if callerDID == "" {
            // No DID claimed, proceed without DID auth
            c.Next()
            return
        }

        // Require signature if DID is claimed
        if signature == "" || timestamp == "" {
            c.AbortWithStatusJSON(401, gin.H{
                "error": "DID claimed but signature missing",
            })
            return
        }

        // Verify timestamp (prevent replay attacks)
        ts, _ := strconv.ParseInt(timestamp, 10, 64)
        if abs(time.Now().Unix() - ts) > 300 { // 5 minute window
            c.AbortWithStatusJSON(401, gin.H{
                "error": "Timestamp too old or too far in future",
            })
            return
        }

        // Build verification payload
        bodyBytes, _ := io.ReadAll(c.Request.Body)
        c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

        payload := fmt.Sprintf("%s:%x", timestamp, sha256.Sum256(bodyBytes))

        // Verify signature against DID document
        sigBytes, _ := base64.StdEncoding.DecodeString(signature)
        valid, err := didWebService.VerifyDIDOwnership(
            c.Request.Context(),
            callerDID,
            []byte(payload),
            sigBytes,
        )

        if err != nil || !valid {
            c.AbortWithStatusJSON(401, gin.H{
                "error": "Invalid DID signature",
            })
            return
        }

        // DID verified - set in context
        c.Set("verified_caller_did", callerDID)
        c.Next()
    }
}
```

### 4. Permission Check Uses Verified DID

```go
// In execute handler
func (h *ExecuteHandler) Execute(c *gin.Context) {
    // Get VERIFIED caller DID (set by middleware)
    callerDID, exists := c.Get("verified_caller_did")
    if !exists {
        // No verified DID - check if target requires permission
        // If target is protected, reject
    }

    // Check permission using verified DID
    check, err := h.permissionService.CheckPermission(
        c.Request.Context(),
        callerDID.(string),
        targetDID,
        targetAgentID,
        targetTags,
    )

    if check.RequiresPermission && !check.HasValidApproval {
        c.AbortWithStatusJSON(403, gin.H{
            "error": "Permission required",
            "status": check.ApprovalStatus,
        })
        return
    }

    // Proceed with execution
}
```

---

## Signature Payload Format

To prevent replay attacks and ensure request integrity:

```
payload = "{timestamp}:{sha256(request_body)}"

Example:
timestamp = 1707091200
body = {"target": "agent-b", "input": {"x": 1}}
body_hash = sha256(body) = "a1b2c3d4..."
payload = "1707091200:a1b2c3d4..."
signature = Ed25519.sign(payload, private_key)
```

### Why This Format?

1. **Timestamp** - Prevents replay attacks (reject if too old)
2. **Body hash** - Ensures request wasn't tampered with
3. **Not including URL** - Allows routing flexibility

---

## Security Guarantees

With this implementation:

| Threat | Protection |
|--------|------------|
| DID spoofing | Signature verification proves key ownership |
| Replay attacks | Timestamp validation (5 min window) |
| Request tampering | Body hash in signature payload |
| Key compromise | DID revocation removes DID document |
| Man-in-middle | HTTPS for transport security |

---

## End-to-End Flow

### 1. Agent Registration

```
Agent                          Control Plane
  │                                  │
  │  POST /register                  │
  │  {agent_id: "my-agent"}         │
  │  ────────────────────────────►   │
  │                                  │
  │                                  │  Generate key pair
  │                                  │  Store DID document
  │                                  │
  │  {                               │
  │    did: "did:web:...:my-agent", │
  │    public_key_jwk: {...},       │
  │    private_key_jwk: {...}  ◄────── One-time delivery
  │  }                               │
  │  ◄────────────────────────────   │
  │                                  │
  │  Store private key securely     │
```

### 2. Agent Calling Protected Agent

```
Agent A                        Control Plane                    Agent B
  │                                  │                             │
  │  1. Build request               │                             │
  │  2. Sign with private key       │                             │
  │                                  │                             │
  │  POST /execute                   │                             │
  │  X-Caller-DID: did:...:agent-a  │                             │
  │  X-DID-Signature: abc123...     │                             │
  │  X-DID-Timestamp: 1707091200    │                             │
  │  {target: "agent-b"}            │                             │
  │  ────────────────────────────►   │                             │
  │                                  │                             │
  │                                  │  3. Verify signature        │
  │                                  │  4. Check timestamp         │
  │                                  │  5. Is agent-b protected?   │
  │                                  │  6. Has agent-a approval?   │
  │                                  │                             │
  │                                  │  If all pass:               │
  │                                  │  ──────────────────────────►│
  │                                  │                             │
  │                                  │  ◄──────────────────────────│
  │  ◄────────────────────────────   │                             │
```

### 3. DID Revocation

```
Admin                          Control Plane                    Agent A
  │                                  │                             │
  │  POST /admin/did/revoke         │                             │
  │  {did: "did:...:agent-a"}       │                             │
  │  ────────────────────────────►   │                             │
  │                                  │                             │
  │                                  │  Mark DID as revoked        │
  │                                  │  (revoked_at timestamp)     │
  │                                  │                             │
  │  ◄────────────────────────────   │                             │
  │                                  │                             │
  │                                  │         Later...            │
  │                                  │                             │
  │                                  │  ◄───────────────────────────
  │                                  │  Agent A tries to call      │
  │                                  │                             │
  │                                  │  Resolve DID → REVOKED      │
  │                                  │  Reject request             │
  │                                  │  ────────────────────────────►
  │                                  │  Error: DID revoked         │
```

---

## Files to Create/Modify

### New Files
- `internal/middleware/did_auth.go` - DID signature verification middleware
- `pkg/types/did_auth_types.go` - Types for authentication

### Modified Files
- `internal/handlers/nodes.go` - Return private key on registration
- `internal/handlers/execute.go` - Use verified DID from context
- `internal/server/server.go` - Add DID auth middleware
- `sdk/python/agentfield/client.py` - Sign requests with private key
- `sdk/go/client/client.go` - Sign requests with private key

---

## Testing Plan

### Unit Tests
1. Signature generation and verification
2. Timestamp validation (accept/reject based on age)
3. Body hash verification

### Integration Tests
1. Registration returns private key
2. Request with valid signature succeeds
3. Request with invalid signature fails
4. Request with old timestamp fails
5. Request with tampered body fails
6. Revoked DID requests fail

### Security Tests
1. Attempt DID spoofing without signature
2. Attempt replay attack with old timestamp
3. Attempt request tampering

---

*End of Security Document*
