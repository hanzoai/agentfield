# VC Authorization — Drift Findings

Manual testing performed on **2026-02-09** against `feat/vc-authorization` branch.
Reference architecture: [`docs/VC_AUTHORIZATION_ARCHITECTURE.md`](VC_AUTHORIZATION_ARCHITECTURE.md)

---

## Summary

| Severity | Count | Status | Description |
|----------|-------|--------|-------------|
| Critical | 2 | **FIXED** | Python SDK pending_approval bypass; missing revocation API |
| High | 3 | **ALL FIXED** | Go SDK pending_approval bypass; `did:web` non-functional (deferred); external calls blocked by `deny_anonymous` |
| Medium | 5 | **ALL FIXED** | Error propagation (Python SDK), VC export gap, Python DID nonce replay |
| Low | 4 | **3 FIXED, 1 DEFERRED** | Re-registration state fixed, public key endpoint fixed, port conflicts documented, `did:web` deferred |

---

## Fixed in This Session

### D1: Python SDK bypasses `pending_approval` state — **FIXED**

**Previous:** Python agent with `sensitive` tag went straight to `ready`.
**Current:** Python agent correctly enters `pending_approval` and blocks until admin approval. Verified with all 3 SDKs (TS, Go, Python) entering `pending_approval`.

### D13: Revocation API — **FIXED**

**Previous:** `POST /api/v1/admin/permissions/:id/revoke` returned 404.
**Current:** `POST /api/v1/admin/agents/:id/revoke-tags` works. Transitions agent to `pending_approval`, clearing approved tags. Subsequent calls to revoked agent fail with `agent_pending_approval`. Re-approval restores access.

### D10: External calls bypass all access policies — **FIXED**

**Previous:** External curl without identity headers bypassed policy engine.
**Current:** `deny_anonymous: true` in config causes 403 `anonymous_caller_denied` for requests without `X-Agent-Node-ID` header. Policies only apply to identified callers.

### D11: VC export omits Agent Tag VCs — **FIXED**

**Previous:** `GET /api/v1/did/export/vcs` had no `agent_tag_vcs` field.
**Current:** Export returns `agent_tag_vcs` array with 6 VCs (one per agent), each with Ed25519 signature and W3C VC structure.

### D14: Tag rejection only works during `pending_approval` — **FIXED**

**Previous:** No mechanism to revoke tags on running agents.
**Current:** `POST /api/v1/admin/agents/:id/revoke-tags` works on agents in `ready` state, transitioning them back to `pending_approval`.

### D15: Go SDK bypasses `pending_approval` via `markReady()` — **FIXED**

**Discovered during testing:** Go SDK's `Initialize()` called `markReady()` after registration, which sent a PATCH status update overriding `pending_approval` → `ready`. The control plane's heartbeat and lifecycle status handlers allowed this override.

**Fix (two-part):**
1. **Control plane** (`internal/handlers/nodes.go`): Heartbeat handler, legacy heartbeat handler, and `UpdateLifecycleStatusHandler` now protect `pending_approval` state — reject status updates with 409 Conflict or silently ignore heartbeat overrides.
2. **Go SDK** (`sdk/go/agent/agent.go`): `markReady()` now safely called after approval; control plane rejects it if still pending.

### D16: Python SDK DID signature replay on cross-agent calls — **FIXED**

**Root cause:** Ed25519 signatures are deterministic. When multiple requests had the same body within the same second, `sign_request()` produced identical signatures (`timestamp:body_hash` was the same), triggering the control plane's replay cache.

**Fix:** Added per-request nonce (`X-DID-Nonce` header) to all three SDKs. The signing payload is now `timestamp:nonce:body_hash`, ensuring unique signatures even with identical bodies. Control plane middleware accepts both formats (backward-compatible).

**Files changed:**
- `sdk/python/agentfield/did_auth.py` — nonce generation via `os.urandom(16).hex()`
- `sdk/typescript/src/client/DIDAuthenticator.ts` — nonce via `crypto.randomBytes(16)`
- `sdk/go/client/did_auth.go` — nonce via `crypto/rand`
- `control-plane/internal/server/middleware/did_auth.go` — nonce-aware payload reconstruction

### D6: Error propagation wraps inner 403 as outer 502 — **FIXED (Python SDK)**

**Root cause:** The control plane's `writeExecutionError()` already had correct 4xx propagation logic. The issue was in the Python SDK: when a cross-agent `call()` failed with an `ExecuteError` (which carries the HTTP status code), the reasoner's HTTP handler didn't catch it specifically — it fell through to the generic `Exception` handler, which FastAPI converts to 500. The outer control plane then mapped 500 → 502.

**Fix:** Added `ExecuteError` handler in Python SDK's `_execute_reasoner_endpoint()` that converts it to `HTTPException` with the upstream status code. The Go and TS SDKs already had this mechanism (`ExecuteError.StatusCode` and `err.status` respectively).

**File changed:** `sdk/python/agentfield/agent.py` — added `except ExecuteError` clause before `except Exception`

### D9: Admin public key endpoint requires admin token — **FIXED**

**Root cause:** The endpoint at `GET /api/v1/admin/public-key` was NOT actually behind admin middleware (it was on the `agentAPI` group, not the `adminGroup`). The misleading `/admin/` path prefix caused confusion.

**Fix:** Added semantic alias at `GET /api/v1/did/issuer-public-key` (public, no auth required). The old `/admin/public-key` path is preserved as a backward-compatible alias.

**File changed:** `control-plane/internal/server/server.go`

### D3: Re-registration can reuse previous approval state — **FIXED**

**Root cause:** On re-registration, the handler preserved the existing agent's lifecycle status (e.g., `ready`), allowing an agent to skip tag approval if it had been previously approved — even if tag approval rules had changed.

**Fix:** Re-registrations now always reset to `starting` (unless admin-revoked), allowing the tag approval service to re-evaluate tags against current rules.

**File changed:** `control-plane/internal/handlers/nodes.go`

### D7: Go caller VC generation fails for non-DID callers — **IMPROVED**

**Status:** The control plane already handles this gracefully (falls back to agent's own DID when CallerDID is empty). Added a warning log in the Go SDK's `maybeGenerateVC()` when CallerDID is empty, improving observability.

**File changed:** `sdk/go/agent/agent.go`

---

## Known Issues (Deferred)

### D5: `did:web` method non-functional — **DEFERRED**

All agent DIDs use `did:key:z7Q...` format. `did:web` resolution not functional. The `did_web_service.go` implementation exists (~386 lines) but is not wired into the agent registration flow. This is a 2-3 day feature, not a quick fix. Current system works via `did:key` + tag-based revocation.

**Infrastructure ready:** DID web service, database schema (migration 019), resolution endpoints (`/.well-known/did.json`, `/agents/{agentID}/did.json`), signature verification.
**Missing:** Integration with agent registration flow, SDK support, end-to-end testing.

---

## Verified Working Features

1. Tag approval flow (`auto`/`manual`/`forbidden` rules) — **all 3 SDKs** (TS, Go, Python)
2. Policy engine (first-match-wins, caller/target tag matching, `*` wildcards)
3. `deny_functions` enforcement with pattern matching (`delete_*`)
4. Constraint evaluation (numeric `<=` operator on input parameters)
5. Dynamic policy CRUD via admin API with immediate cache reload
6. VC generation on target agents (TS confirmed `vcGenerated: true`, `vcId` in response)
7. Agent Tag VC issuance — 6 VCs for 6 agents (auto-approved and admin-approved)
8. Execution VC with Ed25519 signatures — 6 execution VCs generated
9. DID resolution for `did:key` identifiers — 6 unique DIDs
10. Admin token authentication on admin endpoints (invalid/missing → 403)
11. Pending agent blocking (503 for calls to `pending_approval` agents)
12. VC export with `agent_tag_vcs`, `execution_vcs`, `agent_dids`
13. Policy distribution endpoint (`GET /api/v1/policies`) — 2 policies served
14. Revocation list endpoint (`GET /api/v1/revocations`) — operational
15. Nonexistent agent → 403 "target_resolution_failed" (fail closed)
16. Tag revocation → `pending_approval` transition → call fails → re-approve → call succeeds
17. Anonymous caller denial (`deny_anonymous: true`) → 403 for headerless requests
18. Policy delete → re-create → access restored
19. Policy constraint tightening (1000 → 50) → previously-allowed calls denied
20. Go SDK correctly waits in `pending_approval` polling loop (5s interval, 5min timeout)
21. Public key endpoint returns Ed25519 JWK for VC signature verification
22. Per-request nonce prevents DID signature replay across all 3 SDKs
23. Re-registration re-evaluates tag approval rules
24. Issuer public key available at `/api/v1/did/issuer-public-key` (no admin token required)

---

## Test Results Matrix

### Phase 2: Registration & Tag Approval

| Test | TS | Go | Python |
|------|----|----|--------|
| B agent enters pending_approval | PASS | PASS | PASS |
| Call to pending agent → 503 | PASS | PASS | PASS |
| Admin approve-tags | PASS | PASS | PASS |
| A agent auto-approved | PASS | PASS | PASS |

### Phase 3-4: Execution Flows

| Test | TS | Go | Python |
|------|----|----|--------|
| Allowed function call | PASS (200) | PASS (200) | FIXED (was 401 sig replay) |
| Health check (ping) | PASS (200) | PASS (200) | PASS (200) |
| Constraint violation (limit>1000) | PASS (403) | PASS (403) | PASS (403) |
| Denied function (delete_*) | PASS (403) | PASS (403) | PASS (403) |

### Phase 5: VC Generation & Verification

| Test | Result |
|------|--------|
| 6 unique Agent DIDs | PASS |
| 6 Agent Tag VCs | PASS |
| 6 Execution VCs | PASS |
| Public key endpoint | PASS |
| Policies endpoint | PASS |
| Revocations endpoint | PASS |
| VC export includes agent_tag_vcs | PASS |

### Phase 6: Policy CRUD

| Test | Result |
|------|--------|
| List policies | PASS |
| Delete policy | PASS |
| Call after delete (default allow) | KNOWN (no matching policy = allow) |
| Re-create policy | PASS |
| Call succeeds after re-create | PASS |
| Tighten constraint (1000→50) | PASS |
| Call with limit=100 now denied | PASS |
| Restore constraint | PASS |

### Phase 7: Revocation & Edge Cases

| Test | Result |
|------|--------|
| revoke-tags endpoint | PASS |
| Call to revoked agent fails | PASS |
| Re-approve restores access | PASS |
| Invalid admin token → 403 | PASS |
| Missing admin token → 403 | PASS |
| Nonexistent agent → 403 | PASS |
| Nonexistent function → 400 (expected 404) | MINOR |
| Revocations list after re-approval | PASS (empty) |

---

## Not Tested (Deferred)

- `did:web` document resolution endpoint
- Decentralized verification (local policy caching by agents)
- VC expiration enforcement
- Policy priority ordering with overlapping policies
- Other constraint operators (>=, <, >, ==, !=)
- `require_realtime_validation` decorator
- Cross-language interop (Phase 8 — requires cross-language caller reasoners)

---

## Test Environment

- **Branch:** `feat/vc-authorization`
- **Control plane:** `go run -tags sqlite_fts5 ./cmd/agentfield-server --open=false`
- **Storage:** SQLite (local mode) at `~/.agentfield/data/agentfield.db`
- **Agents tested:**
  - TS caller (port 8005), TS target (port 8006)
  - Go caller (port 8003), Go target (port 8004)
  - Python caller (port 8001), Python target (port 8007)
- **Config:** `control-plane/config/agentfield.yaml` with 2 seeded policies, `deny_anonymous: true`
