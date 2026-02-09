# VC Authorization — Drift Findings

Manual testing performed on **2026-02-09** against `feat/vc-authorization` branch.
Reference architecture: [`docs/VC_AUTHORIZATION_ARCHITECTURE.md`](VC_AUTHORIZATION_ARCHITECTURE.md)

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 2 | Python SDK bypasses tag approval; missing revocation API |
| High | 3 | Go caller VC fails; `did:web` non-functional; external calls bypass policies |
| Medium | 5 | Error propagation, Python VC logging, export gaps, tag rejection limits |
| Low | 4 | Naming/endpoint inconsistencies, re-registration state, internal token docs |

---

## Critical

### D1: Python SDK bypasses `pending_approval` state

**Observed:** Python agent-b with `sensitive` tag (configured as `manual` approval in `tag_approval_rules`) goes straight to `ready` instead of entering `pending_approval`.

**Expected:** Agent should enter `pending_approval` and block until an admin calls `POST /api/v1/admin/agents/:id/approve-tags`.

**Impact:** Python agents skip the entire tag approval flow. Any Python agent can self-approve tags that require manual review.

**Reproduction:**
```bash
# Python agent registers with sensitive tag → immediately ready
python3 -c "
from agentfield import Agent
app = Agent(node_id='test-b', agentfield_server='http://localhost:8080',
            tags=['sensitive','data-service'], enable_did=True, vc_enabled=True)
app.run(port=8009)
"
# Check: lifecycle_status is 'ready', not 'pending_approval'
```

**Go/TS SDKs:** Correctly enter `pending_approval` and poll until approved.

### D13: Revocation API described in arch doc does not exist

**Observed:** `POST /api/v1/admin/permissions/:id/revoke` returns 404 "endpoint not found".

**Expected:** Arch doc (line ~529) describes a revocation flow where approved tags/DIDs can be revoked.

**Impact:** Once a DID or tag is approved, there is no admin mechanism to revoke it. The `GET /api/v1/revocations` endpoint works but always returns an empty list because nothing can add entries to it.

---

## High

### D7: Go caller agent VC generation fails for non-DID-authenticated callers

**Observed:** When a request without DID authentication (e.g., curl) reaches a Go caller agent, the agent's VC generation fails:
```
VC generation failed: server returned 500:
{"details":"failed to resolve caller DID: DID not found: ","error":"Failed to generate execution VC"}
```

**Root cause:** The `X-Caller-DID` header is empty for non-DID-authenticated requests. The Go SDK reads `CallerDID` from this header and passes it to the VC generation endpoint. The server-side `VCService.GenerateExecutionVC` then tries to resolve an empty DID string, which fails.

**Impact:** VC generation fails on caller agents whenever the originating request lacks DID authentication. Target agents work correctly because the control plane forwards `X-Caller-DID` for cross-agent calls.

**Affected code:** `sdk/go/agent/agent.go:1121` (reads header), `control-plane/internal/services/vc_service.go:165` (fails on empty DID).

### D5: `did:web` method non-functional; implementation uses `did:key`

**Observed:**
- All agent DIDs are `did:key:z7Q...` format
- Issuer DID is `did:key:z7QEFj...`, not `did:web:localhost%3A8080:agents:control-plane` as described in arch doc
- `GET /api/v1/did/resolve/did:web:localhost%3A8080:agents:ts-perm-target` returns "DID not found"

**Expected:** Arch doc describes `did:web` as the primary method: *"did:web enables real-time revocation via control plane-hosted DID documents"*.

**Impact:** The `did:web` resolution and revocation model described in the architecture is not implemented. All identity is `did:key`-based, which doesn't support server-side revocation.

### D10: External calls bypass all access policies

**Observed:** A direct HTTP request (e.g., curl) without agent identity headers bypasses the permission middleware entirely. The call succeeds even when a policy would deny it for inter-agent calls.

**Mechanism:** The permission middleware resolves caller tags from the caller's agent identity. External callers have no DID, no `X-Caller-Agent-ID` header, and no `X-Agent-Node-ID` header, so `callerTags` is empty. No policy matches empty caller tags → default is "allow" (backward compatibility).

**Example:**
```bash
# This succeeds even though analytics→data-service policy denies delete_*
curl -X POST http://localhost:8080/api/v1/execute/ts-perm-target.delete_records \
  -H "Content-Type: application/json" -d '{"input": {"table": "test"}}'
# → 200 OK (bypasses policy)

# But cross-agent call is correctly denied:
curl -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_delete \
  -H "Content-Type: application/json" -d '{"input": {}}'
# → 502 (inner 403 Access denied by policy)
```

**Impact:** Any unauthenticated external caller can reach any agent function, regardless of access policies. Policies only enforce inter-agent boundaries.

---

## Medium

### D2: Python agent-b approval returns HTTP 500 instead of 400/409

Calling `POST /api/v1/admin/agents/permission-agent-b/approve-tags` on an already-ready Python agent returns `500 "not pending approval"` instead of a client error (400 or 409).

### D6: Error propagation wraps inner 403 as outer 502

When a cross-agent call is denied by policy (inner 403), the outer response to the original caller is 502 Bad Gateway. This is technically correct (the delegated call failed) but obscures the root cause. All three SDKs exhibit this behavior.

### D8: Python agents produce no VC generation logging

Python agent logs show no VC-related output despite `vc_enabled=True` and `enable_did=True`. TS and Go agents log VC generation events. Either the Python SDK doesn't generate VCs or it doesn't log the activity.

### D11: VC export omits Agent Tag VCs

`GET /api/v1/did/export/vcs` returns `execution_vcs` and `workflow_vcs` but has no `agent_tag_vcs` field. Individual tag VCs are accessible via `GET /api/v1/agents/:id/tag-vc`.

### D14: Tag rejection only works during `pending_approval`

`POST /api/v1/admin/agents/:id/reject-tags` returns "not pending approval" for agents in `ready` state. There is no mechanism to revoke previously-approved tags on a running agent. Combined with D13 (no revocation API), approved agents cannot have their privileges reduced without restarting the control plane.

---

## Low

### D3: Re-registration can reuse previous approval state

If an agent restarts and re-registers while the control plane still has its previous registration, the agent may inherit the prior approval state (skipping `pending_approval`). Behavior varies by timing relative to the heartbeat/cleanup cycle.

### D4: Go agents require undocumented `AGENTFIELD_INTERNAL_TOKEN`

Go example agents set `RequireOriginAuth: true`, which requires `AGENTFIELD_INTERNAL_TOKEN=internal-secret-token` environment variable. This is not documented in the testing plan or architecture doc.

### D9: Admin public key endpoint requires admin token

`GET /api/v1/admin/public-key` requires `X-Admin-Token` header. The arch doc describes agents caching the admin public key locally for offline verification, but agents would need the admin token to fetch it. This contradicts the public-key distribution model.

### D12: Python agent-b has no Agent Tag VC

Since Python agent-b bypasses `pending_approval` (D1), no Agent Tag VC is issued for it. The tag VC verifier falls back to registration tags for policy evaluation, which still works but lacks cryptographic proof of approval.

---

## Verified Working Features

1. Tag approval flow (`auto`/`manual`/`forbidden` rules) — Go and TS SDKs
2. Policy engine (first-match-wins, caller/target tag matching, `*` wildcards)
3. `deny_functions` enforcement with pattern matching
4. Constraint evaluation (numeric `<=` operator on input parameters)
5. Dynamic policy CRUD via admin API with immediate cache reload
6. VC generation on target agents (TS, Go)
7. Agent Tag VC issuance upon admin approval
8. Execution VC with Ed25519 signatures and W3C VC structure
9. Workflow VC chain construction with DID resolution bundle
10. DID resolution for `did:key` identifiers
11. Admin token authentication on admin endpoints
12. Pending agent blocking (503 for calls to `pending_approval` agents)
13. VC export (execution VCs with DID bundle)
14. Policy distribution endpoint (`GET /api/v1/policies`) for agent caching
15. Nonexistent agent → 403 "target_resolution_failed" (fail closed)
16. Nonexistent function → appropriate error from target agent

---

## Test Environment

- **Branch:** `feat/vc-authorization`
- **Control plane:** `go run -tags sqlite_fts5 ./cmd/agentfield-server --open=false -v`
- **Storage:** SQLite (local mode) at `~/.agentfield/data/agentfield.db`
- **Agents tested:**
  - TS caller (port 8005), TS target (port 8006)
  - Go caller (port 8003), Go target (port 8004)
  - Python caller (port 8001), Python target (port 8009)
- **Config:** `control-plane/config/agentfield.yaml` with 2 seeded policies
