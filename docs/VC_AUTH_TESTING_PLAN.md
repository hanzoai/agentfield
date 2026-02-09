# VC Authorization Manual Testing Plan

End-to-end manual testing of the VC authorization system across all three SDK languages (TypeScript, Go, Python).

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Agent Inventory](#2-agent-inventory)
3. [Example Gap Analysis — What Needs to Be Built](#3-example-gap-analysis--what-needs-to-be-built)
4. [Test Matrix](#4-test-matrix)
5. [Phase 1: Control Plane Startup](#phase-1-control-plane-startup)
6. [Phase 2: Agent Registration & Tag Approval](#phase-2-agent-registration--tag-approval)
7. [Phase 3: Allowed Execution Flows](#phase-3-allowed-execution-flows)
8. [Phase 4: Denied Execution Flows](#phase-4-denied-execution-flows)
9. [Phase 5: VC Generation & Verification](#phase-5-vc-generation--verification)
10. [Phase 6: Access Policy CRUD & Dynamic Changes](#phase-6-access-policy-crud--dynamic-changes)
11. [Phase 7: Revocation & Edge Cases](#phase-7-revocation--edge-cases)
12. [Phase 8: Cross-Language Interop](#phase-8-cross-language-interop)
13. [Quick Reference: All curl Commands](#quick-reference-all-curl-commands)

---

## 1. Environment Setup

### Prerequisites

- Go 1.23+
- Node.js 20+ with `tsx` installed
- Python 3.8+ with `pip`
- 7 terminal windows (1 control plane + 6 agents)

### Terminal Layout

| Terminal | Purpose | Directory |
|----------|---------|-----------|
| T1 | Control Plane | `control-plane/` |
| T2 | TS Agent A (caller) | `examples/ts-node-examples/` |
| T3 | TS Agent B (target) | `examples/ts-node-examples/` |
| T4 | Go Agent A (caller) | `examples/go_agent_nodes/` |
| T5 | Go Agent B (target) | `examples/go_agent_nodes/` |
| T6 | Python Agent A (caller) | `examples/python_agent_nodes/permission_agent_a/` |
| T7 | Python Agent B (target) | `examples/python_agent_nodes/permission_agent_b/` |
| T8 | curl / test runner | anywhere |

### Config Already in Place

The `control-plane/config/agentfield.yaml` already has:
- `features.did.authorization.enabled: true`
- `admin_token: "admin-secret"`
- `internal_token: "internal-secret-token"`
- Tag approval rules: `sensitive/financial/payments` = manual, `public/analytics` = auto
- Access policy: `analytics -> data-service` with `allow_functions: [query_*, get_*, analyze_*]`, `deny_functions: [delete_*, update_*]`, `constraints: {limit: {operator: "<=", value: 1000}}`

### Step 0: Clean Slate (MUST DO BEFORE EVERY TEST RUN)

A clean DB is critical. Stale DID registries cause key mismatches (DID from old seed + private key from new seed = invalid signatures). Stale agent records cause approval state to carry over between runs.

```bash
# 1. Kill any running control plane or agent processes
pkill -f "agentfield-server" 2>/dev/null || true
pkill -f "af dev" 2>/dev/null || true
pkill -f "permission.agent" 2>/dev/null || true
pkill -f "perm-caller\|perm-target" 2>/dev/null || true

# 2. Wipe ALL AgentField data — DB, DID registries, keys, payloads
rm -rf ~/.agentfield/data/ \
       ~/.agentfield/did_registries/ \
       ~/.agentfield/keys/ \
       ~/.agentfield/payloads/

# 3. Also clean the control-plane local data dir (if it exists)
rm -rf control-plane/data/

# 4. Verify clean
ls ~/.agentfield/ 2>/dev/null || echo "~/.agentfield/ does not exist (clean)"
```

### Agent Environment Variables

Go agents using `RequireOriginAuth: true` need the internal token so the control plane can invoke them:

```bash
export AGENTFIELD_INTERNAL_TOKEN=internal-secret-token
```

This must match `features.did.authorization.internal_token` in `agentfield.yaml`. Without it, the control plane's forwarded requests to the agent will be rejected with an auth error.

### Startup Order

After this, start the control plane (Phase 1), then spin up agents (Phase 2). The startup order matters:
1. Control plane first
2. Target agents (B) second — they enter `pending_approval`
3. Admin approves target agents
4. Caller agents (A) last — they auto-approve and can immediately call targets

---

## 2. Agent Inventory

### TypeScript Agents (ports 8005/8006)

| Agent | Node ID | Tags | Approval | Port |
|-------|---------|------|----------|------|
| TS-A (caller) | `ts-perm-caller` | `["analytics"]` | auto | 8005 |
| TS-B (target) | `ts-perm-target` | `["sensitive", "data-service"]` | manual | 8006 |

**TS-A reasoners:** `ping`, `call_analytics`, `call_large_query`, `call_delete`
**TS-B reasoners:** `analyze_data`, `delete_records`, `get_schema`

### Go Agents (ports 8003/8004)

| Agent | Node ID | Tags | Approval | Port |
|-------|---------|------|----------|------|
| Go-A (caller) | `go-perm-caller` | `["analytics"]` | auto | 8003 |
| Go-B (target) | `go-perm-target` | `["sensitive", "data-service"]` | manual | 8004 |

**Go-A reasoners:** `ping`, `call_data_service`, `call_large_query`, `call_delete_records`
**Go-B reasoners:** `query_data`, `delete_records`, `get_schema`

### Python Agents (auto-port)

| Agent | Node ID | Tags | Approval | Port |
|-------|---------|------|----------|------|
| Py-A (caller) | `permission-agent-a` | `["analytics"]` | auto | auto |
| Py-B (target) | `permission-agent-b` | `["sensitive", "data-service", "payments"]` | manual | auto |

**Py-A reasoners:** `ping`, `call_query_data`, `call_query_large`, `call_delete`
**Py-B skills:** `query_data`, `delete_records`, `process_payment`

---

## 3. Example Gap Analysis — What Needs to Be Built

The existing examples cover the basic allow/deny/constraint flows within same-language pairs. Several test phases require additions to the examples before they can be executed. **These must be built before testing begins.**

### Priority Summary

| # | Gap | Severity | Blocks |
|---|-----|----------|--------|
| G1 | Cross-language interop calls missing | **HIGH** | Phase 8 |
| G2 | VC generation missing in Go-B and Py-B reasoner code | **HIGH** | Phase 5 (Go, Python) |
| G3 | `process_payment` is dead code — no payments caller exists | **HIGH** | Payments policy testing |
| G4 | No `call_get_schema` caller reasoner (any language) | MEDIUM | `get_*` wildcard validation |
| G5 | `get_schema` missing from Python Agent B | MEDIUM | Python parity |
| G6 | No `refund_*` function to test payments deny path | MEDIUM | Payments deny testing |
| G7 | Error propagation (403 vs 500) untested | MEDIUM | Phase 4 correctness |
| G8 | No VC-level revocation testing | MEDIUM | Phase 7 (revocation) |
| G9 | No edge case / malformed input testing | LOW | Robustness |
| G10 | No agent-side dynamic policy cache testing | LOW | Phase 6 agent behavior |

---

### G1: Cross-Language Interop Calls (HIGH — Blocks Phase 8)

**Problem:** Each caller agent only calls its own-language target. Phase 8 (Cross-Language Interop) has zero agent support.

**What to build on each caller agent:**

**TS-A** — add 2 new reasoners:
```typescript
agent.reasoner('call_go_target', async (ctx) => {
  return await agent.call('go-perm-target.query_data', { query: ctx.input.query ?? 'cross-lang', limit: 100 });
}, { description: 'Cross-lang: TS -> Go', tags: ['analytics'] });

agent.reasoner('call_py_target', async (ctx) => {
  return await agent.call('permission-agent-b.query_data', { query: ctx.input.query ?? 'cross-lang', limit: 100 });
}, { description: 'Cross-lang: TS -> Python', tags: ['analytics'] });
```

**Go-A** — add 2 new skills:
```go
// call_ts_target: calls ts-perm-target.analyze_data
// call_py_target: calls permission-agent-b.query_data
```

**Py-A** — add 2 new reasoners:
```python
@app.reasoner()
async def call_ts_target(query: str = "cross-lang") -> dict:
    return await app.call("ts-perm-target.analyze_data", query=query, limit=100)

@app.reasoner()
async def call_go_target(query: str = "cross-lang") -> dict:
    return await app.call("go-perm-target.query_data", query=query, limit=100)
```

This enables the full 6-combination interop matrix: TS->Go, TS->Py, Go->TS, Go->Py, Py->TS, Py->Go.

---

### G2: VC Generation Missing in Go-B and Py-B (HIGH — Blocks Phase 5)

**Problem:** Only TS-B explicitly calls `ctx.did.generateCredential()` in its `analyze_data` reasoner. Go-B and Py-B have `VCEnabled: true` / `vc_enabled=True` in config but never generate VCs in their reasoner code. Phase 5 expects `vcGenerated: true` in responses from all languages.

**What to build:**

**Go-B** — add VC generation in `query_data`:
```go
// After computing the result, call the VC generation API:
// credential, err := ctx.DID.GenerateCredential(...)
// result["vc_generated"] = true
// result["vc_id"] = credential.VCID
```
*Investigate:* Does the Go SDK expose `ctx.DID.GenerateCredential()` or equivalent? If VCs are generated automatically at the framework level, the reasoner just needs to surface the metadata in its response.

**Py-B** — add VC generation in `query_data`:
```python
# After computing the result, call the VC generation API:
# credential = await ctx.did.generate_credential(...)
# result["vc_generated"] = True
# result["vc_id"] = credential.vc_id
```
*Investigate:* Does the Python SDK expose VC generation in the execution context? Same question as Go.

---

### G3: `process_payment` Is Dead Code (HIGH)

**Problem:** The `payments_to_payments` policy is seeded in config but has no caller agent. Py-B has `process_payment` but no agent has `["payments"]` caller tag, so this policy and skill are entirely untestable.

**Options (pick one):**

**Option A — Add a payments caller agent (new agent, one language):**
Create a lightweight `permission_agent_c` (e.g., in Python) with `tags: ["payments"]` and reasoners:
- `call_process_payment` — calls `permission-agent-b.process_payment` with `amount=500` (ALLOWED, <= 10000)
- `call_large_payment` — calls with `amount=50000` (DENIED, constraint > 10000)
- `call_refund` — calls `permission-agent-b.refund_payment` (DENIED, deny_functions)

**Option B — Extend Py-A with dual tags:**
Add `"payments"` to Py-A's tags: `tags=["analytics", "payments"]` and add payment caller reasoners. Simpler, but muddies the analytics/payments separation.

**Also needed on Py-B:** Add a `refund_payment` skill to test the `refund_*` deny_functions path (see G6).

---

### G4: No `call_get_schema` Caller Reasoner (MEDIUM)

**Problem:** All three target agents (TS-B, Go-B) have `get_schema`, but no caller agent calls it. The `get_*` wildcard in the access policy is never tested.

**What to build on each caller agent:**

```
# Each caller: add call_get_schema reasoner that calls <target>.get_schema
# Expected: 200 OK (get_* matches allow_functions)
```

---

### G5: `get_schema` Missing from Python Agent B (MEDIUM)

**Problem:** TS-B and Go-B both have `get_schema`, but Py-B does not. Breaks Python parity.

**What to build on Py-B:**
```python
@app.skill(tags=["data-service"])
def get_schema() -> dict:
    return {
        "status": "success",
        "agent": "permission-agent-b",
        "schema": {
            "table": "records",
            "columns": [
                {"name": "id", "type": "integer", "primary_key": True},
                {"name": "name", "type": "text", "primary_key": False},
                {"name": "created_at", "type": "timestamp", "primary_key": False},
            ],
        },
    }
```

---

### G6: No `refund_*` Function for Payments Deny Path (MEDIUM)

**Problem:** The `payments_to_payments` policy has `deny_functions: ["refund_*"]` but no target agent has a `refund_*` function.

**What to build on Py-B:**
```python
@app.skill(tags=["payments"])
def refund_payment(amount: float, currency: str = "USD") -> dict:
    return {"status": "refunded", "amount": amount, "currency": currency}
```

---

### G7: Error Propagation — 403 vs 500 (MEDIUM)

**Problem:** When the control plane denies a cross-agent call (403), the caller agent's response to the original requester may return 500 instead of propagating the 403. This is especially likely in Python (no try/except around `app.call()`).

**What to verify:**
- TS-A: Does `agent.call()` throw? Does the 403 propagate?
- Go-A: The `err != nil` path wraps the error — does the SDK return 403 or 500?
- Py-A: `await app.call()` with no try/except — FastAPI will likely return 500.

**What to build (if needed):** Add try/except wrappers in callers to catch and re-raise with proper HTTP status codes. Or verify the SDKs handle this automatically.

---

### G8: VC-Level Revocation Testing (MEDIUM)

**Problem:** Phase 7 tests tag rejection (admin rejects agent's tags) but does NOT test VC-level revocation (admin revokes a specific VC). The `/api/v1/revocations` endpoint is checked for emptiness but never populated.

**What to build:** This is primarily a curl-based test, not agent code. Need to determine:
1. Does an admin API exist to revoke a specific VC? (e.g., `POST /api/v1/admin/revocations`)
2. After revocation, does the next call using that VC chain fail?

If the API exists, add curl commands to Phase 7. If it doesn't exist, this is a control plane feature gap.

---

### G9: Edge Case / Malformed Input (LOW)

**Problem:** No agents test calling with empty input, missing required fields, wrong types, or extra fields.

**What to build (optional):** Add test reasoners on callers:
```
call_empty_input     -> calls target with {}
call_wrong_type      -> calls target with limit="not_a_number"
call_extra_fields    -> calls target with unexpected additional fields
```

---

### G10: Agent-Side Policy Caching (LOW)

**Problem:** Go-A sets `LocalVerification: true` but no test verifies the agent correctly fetches and caches policies, or updates its cache when policies change on the control plane.

**What to build (optional):** This would require observing agent logs or adding debug endpoints. Low priority for manual testing.

---

### Build Order Recommendation

1. **G5** — Add `get_schema` to Py-B (5 min, prerequisite for G4)
2. **G6** — Add `refund_payment` to Py-B (5 min, prerequisite for G3)
3. **G2** — Add VC generation in Go-B and Py-B reasoners (30 min, investigate SDK APIs first)
4. **G4** — Add `call_get_schema` to all 3 callers (15 min)
5. **G3** — Add payments caller (Option A or B) + reasoners (30 min)
6. **G1** — Add cross-language interop reasoners to all 3 callers (20 min)
7. **G7** — Verify error propagation, fix if needed (15 min)
8. **G8** — Investigate VC revocation admin API, add curl tests (15 min)

Total estimated build time: ~2-3 hours before testing can begin.

---

## 4. Test Matrix

Each test is run against all three language pairs. Expected outcomes:

| # | Test Case | Caller | Target | Expected | HTTP |
|---|-----------|--------|--------|----------|------|
| 1 | Agent B starts in pending_approval | - | B | `pending_approval` status | - |
| 2 | Call to pending agent rejected | A | B | Blocked | 503 |
| 3 | Admin approves agent B tags | - | B | Transitions to `starting` | 200 |
| 4 | Agent A auto-approved on register | A | - | Immediately active | - |
| 5 | Allowed function call (small limit) | A | B | Success | 200 |
| 6 | Constraint violation (large limit) | A | B | Denied | 403 |
| 7 | Denied function (delete) | A | B | Denied | 403 |
| 8 | VC generated on successful exec | A | B | `vcGenerated: true` | 200 |
| 9 | Health check (no cross-agent) | A | - | Success | 200 |
| 10 | Policy removed -> access denied | A | B | Denied | 403 |
| 11 | Policy re-added -> access restored | A | B | Success | 200 |
| 12 | Cross-language call (TS-A -> Go-B) | TS-A | Go-B | Success | 200 |

---

## Phase 1: Control Plane Startup

> **Prerequisite:** Complete [Step 0: Clean Slate](#step-0-clean-slate-must-do-before-every-test-run) first. Every test run must begin from a fresh DB.

### T1: Start the control plane

```bash
cd control-plane
go run ./cmd/af dev
```

Watch the logs for:
- `"authorization enabled"` or similar — confirms VC auth is active
- `"seeding access policies"` — confirms the YAML policies are loaded
- No DID key errors — a clean slate prevents stale key issues

### Verify

```bash
# Health check
curl -s http://localhost:8080/api/v1/health | jq .

# Verify authorization is enabled
curl -s http://localhost:8080/api/v1/policies | jq .

# Verify admin endpoint works
curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies | jq .
```

**Expected:**
- Health returns `{"status": "ok"}`
- `/api/v1/policies` returns the configured policies
- Admin policies endpoint returns the seeded `analytics_to_data_service` and `payments_to_payments` policies

---

## Phase 2: Agent Registration & Tag Approval

### Step 2.1: Start all target agents (B agents) FIRST

They have `sensitive` tag -> should enter `pending_approval`.

**T3 (TS-B):**
```bash
cd examples/ts-node-examples
npm install
AGENTFIELD_URL=http://localhost:8080 npm run dev:perm-b
```

**T5 (Go-B):**
```bash
cd examples/go_agent_nodes
go run ./cmd/permission_agent_b
```

**T7 (Py-B):**
```bash
cd examples/python_agent_nodes/permission_agent_b
pip install -e ../../../sdk/python  # if not already installed
python main.py
```

### Verify: All B agents in pending_approval

```bash
# Check pending agents
curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/agents/pending | jq .
```

**Expected:** All three target agents listed:
- `ts-perm-target` with proposed tags `["sensitive", "data-service"]`
- `go-perm-target` with proposed tags `["sensitive", "data-service"]`
- `permission-agent-b` with proposed tags `["sensitive", "data-service", "payments"]`

### Step 2.2: Test call to pending agent (should fail)

```bash
# Try calling a pending agent - should get 503
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-target.analyze_data \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "test", "limit": 100}}'
```

**Expected:** HTTP 503 with `agent_pending_approval` error message.

### Step 2.3: Approve all B agents

```bash
# Approve TS target
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/ts-perm-target/approve-tags \
  -d '{"approved_tags": ["sensitive", "data-service"], "reason": "Manual test approval"}' | jq .

# Approve Go target
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/go-perm-target/approve-tags \
  -d '{"approved_tags": ["sensitive", "data-service"], "reason": "Manual test approval"}' | jq .

# Approve Python target
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/permission-agent-b/approve-tags \
  -d '{"approved_tags": ["sensitive", "data-service", "payments"], "reason": "Manual test approval"}' | jq .
```

**Expected:** Each returns 200 with updated agent info showing `approved_tags` set.

### Verify: Pending list is now empty

```bash
curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/agents/pending | jq .
```

**Expected:** Empty `agents` array or `total: 0`.

### Step 2.4: Start all caller agents (A agents)

They have `analytics` tag -> should auto-approve and go active immediately.

**T2 (TS-A):**
```bash
cd examples/ts-node-examples
AGENTFIELD_URL=http://localhost:8080 npm run dev:perm-a
```

**T4 (Go-A):**
```bash
cd examples/go_agent_nodes
go run ./cmd/permission_agent_a
```

**T6 (Py-A):**
```bash
cd examples/python_agent_nodes/permission_agent_a
python main.py
```

### Verify: All agents registered and active

```bash
# List all agents
curl -s http://localhost:8080/api/v1/nodes | jq '.[] | {id: .id, status: .status, tags: .tags, approved_tags: .approved_tags}'
```

**Expected:** 6 agents, all with `status` of `active` or `ready`. Caller agents have `analytics` in tags, target agents have `sensitive`/`data-service`.

---

## Phase 3: Allowed Execution Flows

These calls should all succeed (200 OK).

### Test 3.1: TypeScript — Allowed function call

```bash
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_analytics \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT count(*) FROM events"}}' | jq .
```

**Expected:**
- HTTP 200
- Response contains `delegation_result` with `status: "analyzed"`, `insights` array
- `vcGenerated: true` and `vcId` present in delegation result

### Test 3.2: Go — Allowed function call

```bash
curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_data_service \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT * FROM users"}}' | jq .
```

**Expected:**
- HTTP 200
- Response contains `delegation_result` with `status: "success"`, `results` array
- Query results returned from `go-perm-target.query_data`

### Test 3.3: Python — Allowed function call

```bash
curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_query_data \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT * FROM metrics"}}' | jq .
```

**Expected:**
- HTTP 200
- Response contains `delegation_result` with `status: "success"`, `results` array

### Test 3.4: Health check (no authorization needed)

```bash
# Each agent's ping/health
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .

curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .

curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .
```

**Expected:** All return 200 with `{status: "ok"}`.

---

## Phase 4: Denied Execution Flows

### Test 4.1: Constraint Violation — limit > 1000

**TypeScript:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_large_query \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT * FROM big_table"}}'
```

**Go:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_large_query \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT * FROM big_table"}}'
```

**Python:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_query_large \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "SELECT * FROM big_table"}}'
```

**Expected:** All return HTTP 403 with constraint violation error. The `limit=5000` exceeds the `<= 1000` policy constraint.

### Test 4.2: Denied Function — delete_*

**TypeScript:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_delete \
  -H "Content-Type: application/json" \
  -d '{"input": {"table": "sensitive_records"}}'
```

**Go:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_delete_records \
  -H "Content-Type: application/json" \
  -d '{"input": {"table": "sensitive_records"}}'
```

**Python:**
```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_delete \
  -H "Content-Type: application/json" \
  -d '{"input": {"table": "sensitive_records"}}'
```

**Expected:** All return HTTP 403 with denied function error. `delete_*` is in the policy's `deny_functions`.

---

## Phase 5: VC Generation & Verification

### Test 5.1: Verify VC was generated on successful call

After running Test 3.1 (TS allowed call), the TS-B agent should have generated a Verifiable Credential.

```bash
# Check VC in the response - the delegation_result should contain:
# vcGenerated: true
# vcId: "vc_..."

# Retrieve the VC chain for the workflow
# First, get the execution ID from the response of Test 3.1
EXEC_ID="<execution_id_from_test_3.1>"

# Get execution details to find workflow_id
curl -s http://localhost:8080/api/v1/executions/$EXEC_ID | jq .
```

**Expected:** Execution record contains VC metadata. The `vcGenerated` field is `true` and a `vcId` is present.

### Test 5.2: Verify DID resolution

```bash
# Check that agents have registered DIDs
curl -s http://localhost:8080/api/v1/nodes/ts-perm-caller | jq '.did'
curl -s http://localhost:8080/api/v1/nodes/ts-perm-target | jq '.did'
curl -s http://localhost:8080/api/v1/nodes/go-perm-caller | jq '.did'
curl -s http://localhost:8080/api/v1/nodes/go-perm-target | jq '.did'
curl -s http://localhost:8080/api/v1/nodes/permission-agent-a | jq '.did'
curl -s http://localhost:8080/api/v1/nodes/permission-agent-b | jq '.did'
```

**Expected:** Each agent has a `did:key:z...` identifier. No two agents share the same DID.

### Test 5.3: Verify issuer public key endpoint

```bash
curl -s http://localhost:8080/api/v1/admin/public-key | jq .
```

**Expected:** Returns the control plane's public key in JWK format for VC signature verification.

### Test 5.4: Verify policies endpoint (for decentralized caching)

```bash
curl -s http://localhost:8080/api/v1/policies | jq .
```

**Expected:** Returns the configured access policies that agents can cache locally.

### Test 5.5: Verify revocations endpoint

```bash
curl -s http://localhost:8080/api/v1/revocations | jq .
```

**Expected:** Returns revocation list (should be empty initially).

---

## Phase 6: Access Policy CRUD & Dynamic Changes

### Test 6.1: List current policies

```bash
curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies | jq .
```

**Expected:** Returns `analytics_to_data_service` and `payments_to_payments` policies.

### Test 6.2: Delete the analytics policy

```bash
# Get the policy ID first
POLICY_ID=$(curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies | jq -r '.[] | select(.name == "analytics_to_data_service") | .id')

echo "Deleting policy ID: $POLICY_ID"

curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X DELETE -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies/$POLICY_ID
```

**Expected:** HTTP 200, policy deleted.

### Test 6.3: Previously-allowed call now fails (no matching policy)

```bash
# This should now fail or behave differently since the policy was removed
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_analytics \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "test"}}'
```

**Expected:** Behavior depends on default policy (no-match = allow for backward compat). If the system defaults to deny when tags are present, this should return 403. Document actual behavior.

### Test 6.4: Re-create the policy

```bash
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/policies \
  -d '{
    "name": "analytics_to_data_service_v2",
    "caller_tags": ["analytics"],
    "target_tags": ["data-service"],
    "allow_functions": ["query_*", "get_*", "analyze_*"],
    "deny_functions": ["delete_*", "update_*"],
    "constraints": {"limit": {"operator": "<=", "value": 1000}},
    "action": "allow",
    "priority": 100
  }' | jq .
```

**Expected:** HTTP 200/201, policy created.

### Test 6.5: Call succeeds again after policy re-added

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_analytics \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "test"}}'
```

**Expected:** HTTP 200, call succeeds again.

### Test 6.6: Update policy — change constraint

```bash
# Get new policy ID
POLICY_ID=$(curl -s -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies | jq -r '.[] | select(.name == "analytics_to_data_service_v2") | .id')

# Tighten constraint from limit <= 1000 to limit <= 50
curl -s -X PUT \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/policies/$POLICY_ID \
  -d '{
    "name": "analytics_to_data_service_v2",
    "caller_tags": ["analytics"],
    "target_tags": ["data-service"],
    "allow_functions": ["query_*", "get_*", "analyze_*"],
    "deny_functions": ["delete_*", "update_*"],
    "constraints": {"limit": {"operator": "<=", "value": 50}},
    "action": "allow",
    "priority": 100
  }' | jq .
```

### Test 6.7: Call with limit=100 now fails (constraint tightened)

```bash
# limit=100 was previously allowed (<=1000) but now fails (<=50)
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_analytics \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "test"}}'
```

**Expected:** HTTP 403, constraint violation (the agent hardcodes `limit: 100` which now exceeds the new `<= 50` constraint).

### Test 6.8: Restore original constraint

```bash
curl -s -X PUT \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/policies/$POLICY_ID \
  -d '{
    "name": "analytics_to_data_service_v2",
    "caller_tags": ["analytics"],
    "target_tags": ["data-service"],
    "allow_functions": ["query_*", "get_*", "analyze_*"],
    "deny_functions": ["delete_*", "update_*"],
    "constraints": {"limit": {"operator": "<=", "value": 1000}},
    "action": "allow",
    "priority": 100
  }' | jq .
```

---

## Phase 7: Revocation & Edge Cases

### Test 7.1: Reject a target agent's tags

```bash
# Reject Go target's tags
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/go-perm-target/reject-tags \
  -d '{"reason": "Testing revocation flow"}' | jq .
```

**Expected:** Agent transitions to `offline` status, tags cleared.

### Test 7.2: Call to rejected agent fails

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_data_service \
  -H "Content-Type: application/json" \
  -d '{"input": {"query": "test"}}'
```

**Expected:** Fails (agent is offline/rejected). Should return an error status.

### Test 7.3: Re-approve to restore access

```bash
curl -s -X POST \
  -H "X-Admin-Token: admin-secret" \
  -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/go-perm-target/approve-tags \
  -d '{"approved_tags": ["sensitive", "data-service"], "reason": "Re-approved after test"}' | jq .
```

### Test 7.4: Invalid admin token rejected

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -H "X-Admin-Token: wrong-token" \
  http://localhost:8080/api/v1/admin/agents/pending
```

**Expected:** HTTP 401 or 403, unauthorized.

### Test 7.5: Missing admin token rejected

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  http://localhost:8080/api/v1/admin/agents/pending
```

**Expected:** HTTP 401, missing authentication.

### Test 7.6: Call to nonexistent agent

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/nonexistent-agent.some_function \
  -H "Content-Type: application/json" \
  -d '{"input": {}}'
```

**Expected:** HTTP 404, agent not found.

### Test 7.7: Call to nonexistent function on valid agent

```bash
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/v1/execute/ts-perm-target.nonexistent_function \
  -H "Content-Type: application/json" \
  -d '{"input": {}}'
```

**Expected:** HTTP 404, function not found.

---

## Phase 8: Cross-Language Interop

Test that the authorization system works when caller and target are different SDK languages. These tests require creating new temporary agents or modifying existing ones. For now, we test by directly calling target agents' functions (simulating cross-language calls through the control plane).

### Test 8.1: Direct calls to each target's allowed functions

```bash
# Call TS target's get_schema (allowed by policy: get_* for analytics->data-service)
# This tests that the get_* wildcard works
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .

# Call Go target's get_schema
curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .

# Call Python target's ping
curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.ping \
  -H "Content-Type: application/json" -d '{"input": {}}' | jq .
```

**Expected:** All return 200 with health check results.

### Test 8.2: Verify all agents have unique DIDs

```bash
# Collect all DIDs and verify uniqueness
for agent in ts-perm-caller ts-perm-target go-perm-caller go-perm-target permission-agent-a permission-agent-b; do
  echo -n "$agent: "
  curl -s http://localhost:8080/api/v1/nodes/$agent | jq -r '.did // "no-did"'
done
```

**Expected:** 6 unique DIDs, all starting with `did:key:z`.

---

## Quick Reference: All curl Commands

### Admin Operations

```bash
# Auth header for all admin calls
ADMIN="-H 'X-Admin-Token: admin-secret'"

# List pending agents
curl -s -H "X-Admin-Token: admin-secret" http://localhost:8080/api/v1/admin/agents/pending | jq .

# Approve tags
curl -s -X POST -H "X-Admin-Token: admin-secret" -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/{AGENT_ID}/approve-tags \
  -d '{"approved_tags": ["tag1", "tag2"], "reason": "reason"}' | jq .

# Reject tags
curl -s -X POST -H "X-Admin-Token: admin-secret" -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/agents/{AGENT_ID}/reject-tags \
  -d '{"reason": "reason"}' | jq .

# CRUD policies
curl -s -H "X-Admin-Token: admin-secret" http://localhost:8080/api/v1/admin/policies | jq .
curl -s -X POST -H "X-Admin-Token: admin-secret" -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/policies -d '{...}' | jq .
curl -s -X PUT -H "X-Admin-Token: admin-secret" -H "Content-Type: application/json" \
  http://localhost:8080/api/v1/admin/policies/{ID} -d '{...}' | jq .
curl -s -X DELETE -H "X-Admin-Token: admin-secret" \
  http://localhost:8080/api/v1/admin/policies/{ID} | jq .
```

### Execute Calls (TS)

```bash
# Allowed
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_analytics \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Constraint violation
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_large_query \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Denied function
curl -s -X POST http://localhost:8080/api/v1/execute/ts-perm-caller.call_delete \
  -H "Content-Type: application/json" -d '{"input": {"table": "test"}}' | jq .
```

### Execute Calls (Go)

```bash
# Allowed
curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_data_service \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Constraint violation
curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_large_query \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Denied function
curl -s -X POST http://localhost:8080/api/v1/execute/go-perm-caller.call_delete_records \
  -H "Content-Type: application/json" -d '{"input": {"table": "test"}}' | jq .
```

### Execute Calls (Python)

```bash
# Allowed
curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_query_data \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Constraint violation
curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_query_large \
  -H "Content-Type: application/json" -d '{"input": {"query": "test"}}' | jq .

# Denied function
curl -s -X POST http://localhost:8080/api/v1/execute/permission-agent-a.call_delete \
  -H "Content-Type: application/json" -d '{"input": {"table": "test"}}' | jq .
```

### Verification Endpoints

```bash
# Public key
curl -s http://localhost:8080/api/v1/admin/public-key | jq .

# Policies (public)
curl -s http://localhost:8080/api/v1/policies | jq .

# Revocations
curl -s http://localhost:8080/api/v1/revocations | jq .

# Agent DIDs
curl -s http://localhost:8080/api/v1/nodes/{AGENT_ID} | jq '.did'
```

---

## Pass/Fail Tracking

| Phase | Test | TS | Go | Python | Notes |
|-------|------|----|----|--------|-------|
| 2 | B starts pending_approval | | | | |
| 2 | Call to pending agent -> 503 | | | | |
| 2 | Admin approves tags | | | | |
| 2 | A auto-approved | | | | |
| 3 | Allowed function call | | | | |
| 3 | Health check (ping) | | | | |
| 4 | Constraint violation -> 403 | | | | |
| 4 | Denied function -> 403 | | | | |
| 5 | VC generated | | | | |
| 5 | DIDs unique | | | | |
| 5 | Public key endpoint | | | | |
| 6 | Policy delete -> behavior change | | | | |
| 6 | Policy re-create -> access restored | | | | |
| 6 | Constraint tightened -> denied | | | | |
| 7 | Tag rejection -> offline | | | | |
| 7 | Invalid admin token -> 401/403 | | | | |
| 7 | Nonexistent agent -> 404 | | | | |
| 8 | Cross-language health checks | | | | |
| 8 | All DIDs unique | | | | |
