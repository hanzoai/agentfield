# VC Authorization: Current vs CTO Vision — Delta Tracker

This doc tracks the gaps between what's implemented today and the CTO's target design. Each item is a discrete work unit.

---

## Status Legend

- [ ] Not started
- [~] In progress
- [x] Done

---

## 1. Tag Approval Workflow

**Current:** Tags are immediately active on registration. No approval needed for tags themselves. Architecture Decision 6 explicitly says "tags are informational only."

**CTO Vision:** Tags are _proposed_ by the developer. Agent enters `PENDING` state and is paused until admin approves (or modifies) the tags. Three approval modes per tag: `auto`, `manual`, `forbidden`.

### Work Items

- [ ] **1a. Tag approval rules config** — New config section `tag_approval_rules` with `auto`/`manual`/`forbidden` modes per tag
- [ ] **1b. Agent pending state** — Agent registration returns `status: "pending_approval"` with `proposed_tags` vs `approved_tags` fields. Agent is not routable until approved.
- [ ] **1c. Admin tag review API** — Endpoints to list pending agents, approve with proposed tags, approve with modified tags, or reject
- [ ] **1d. SDK pending state handling** — SDK blocks/polls after registration, shows "Waiting for admin approval" until tags are approved
- [ ] **1e. Admin UI for tag review** — UI page showing pending agents with proposed tags, approve/modify/reject actions

---

## 2. Per-Skill Tags

**Current:** Tags are agent-level only: `Agent(tags=["finance"])`.

**CTO Vision:** Tags are declared per-skill: `@app.skill("charge_customer", tags=["finance", "payment"])`. Each skill on the same agent can have different tags.

### Work Items

- [ ] **2a. SDK skill-level tags** — `@app.skill()` and `@app.reasoner()` accept a `tags` parameter
- [ ] **2b. Registration payload change** — Send per-skill tags in registration: `{"skills": [{"name": "charge_customer", "proposed_tags": ["finance", "payment"]}]}`
- [ ] **2c. Control plane storage** — Store and serve per-skill tags alongside agent-level tags
- [ ] **2d. Tag approval applies per-skill** — Admin approves/modifies tags at the skill level, not just agent level

---

## 3. Access Policies (Policy Engine)

**Current:** Binary permission per `(caller_did, target_did)` pair. All-or-nothing per agent.

**CTO Vision:** Rich tag-based policies: caller_tags -> target_tags, per-function allow/deny lists, parameter constraints (e.g. `amount <= 10000`).

### Work Items

- [ ] **3a. Access policy config** — New config section `access_policies` with `caller_tags`, `target_tags`, `allow_functions`, `deny_functions`, `constraints`
- [ ] **3b. Policy storage** — DB table and storage methods for access policies (CRUD)
- [ ] **3c. Policy evaluation engine** — Given caller tags + target tags + function name + input params, find matching policy and evaluate allow/deny/constraints
- [ ] **3d. Replace binary permission check** — Execute handler uses policy engine instead of `(caller_did, target_did)` pair lookup
- [ ] **3e. Constraint evaluation** — Parse and enforce parameter constraints (`amount <= 10000`) at call time
- [ ] **3f. Admin API for policies** — CRUD endpoints for access policies
- [ ] **3g. Admin UI for policies** — UI page to manage access policies

---

## 4. PermissionVC Structure

**Current:** PermissionVC is per `(caller, target)` approval. Contains caller DID, target DID, admin who approved.

**CTO Vision:** PermissionVC is per _agent_, issued when admin approves tags. Contains agent DID and approved tags array. Signed by admin's key.

### Work Items

- [ ] **4a. Agent PermissionVC** — Issue a PermissionVC to each agent when their tags are approved, containing `{did, approved_tags, expiry}`
- [ ] **4b. PermissionVC signature** — Sign the VC with admin/control-plane Ed25519 key (currently `proof.type = "UnsignedAuditRecord"`)
- [ ] **4c. PermissionVC verification at call time** — Control plane loads caller's PermissionVC, verifies signature, checks tags match policy

---

## 5. Decentralized Verification

**Current:** Every call is verified at the control plane (centralized enforcement point).

**CTO Vision:** Agents cache admin public keys, policies, and revocation lists. Verify locally without hitting control plane for every call. Control plane only needed for issuing VCs, publishing revocations, and serving policy updates.

### Work Items

- [ ] **5a. Policy distribution endpoint** — `GET /api/v1/policies` returns current policies for agents to cache
- [ ] **5b. Revocation list endpoint** — `GET /api/v1/revocations` returns revoked DIDs/VCs for agents to cache
- [ ] **5c. SDK local verification** — SDK caches policies + revocation list (refresh every ~5 min), verifies caller PermissionVCs locally
- [ ] **5d. `@app.require_realtime_validation()` decorator** — Opt-in per-function to force control-plane verification instead of cached

---

## ~~6. DID Generation Location~~ — RESOLVED

Keeping `did:web` for revocability. CTO doc references `did:key` but `did:web` is strictly better here since it supports real-time revocation via control plane.

---

## Suggested Implementation Order

| Priority | Item                               | Rationale                                                                                             |
| -------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------- |
| P0       | 1a-1e (Tag approval workflow)      | Foundational — changes the trust model from "tags are informational" to "tags are the auth primitive" |
| P0       | 2a-2d (Per-skill tags)             | Required for policy engine to work at function granularity                                            |
| P1       | 3a-3g (Policy engine)              | Core CTO feature — replaces binary permission model                                                   |
| P1       | 4a-4c (PermissionVC restructure)   | Enables cryptographic verification of tag assignments                                                 |
| P2       | 5a-5d (Decentralized verification) | Performance optimization — can ship centralized first                                                 |

---

## What's Already Done (No Changes Needed)

These pieces from the current implementation align with the CTO vision and carry forward:

- DID-based cryptographic identity (Ed25519 key pairs)
- Signature verification on every request (`X-Caller-DID` / `X-DID-Signature` / `X-DID-Timestamp`)
- Admin approve/reject/revoke workflow and API
- Admin UI infrastructure (pending permissions, history, protected agents pages)
- VC audit trail for executions (ExecutionVC, WorkflowVC)
- Real-time revocation capability
- DID auth middleware
- SDK DID signing (Python, Go, TS)

Original DX Doc:

### **Phase 1: Admin Sets Up System (One-Time Setup)**

Admin configures **two separate things**:

### **1a. Tag Approval Rules (Who gets what tags)**

`# config/tag_rules.yaml

tag_approval_rules:

# Rule 1: Some tags auto-approved

- tags: [internal, experimental, beta]
  approval: auto
  reason: "Safe tags, no special privileges"

# Rule 2: Sensitive tags need approval

- tags: [finance, billing, admin]
  approval: manual
  reason: "Privileged access, requires admin review"

# Rule 3: Forbidden tags (never allowed)

- tags: [root, superuser, god-mode]
  approval: forbidden
  reason: "These tags should not exist"`

**This says:** "When an agent registers and requests these tags, auto-approve vs. manual approve vs. reject"

### **1b. Access Policies (What tags can call what)**

`# config/access_policies.yaml

access_policies:

# Policy 1: Finance can call billing

- name: finance*to_billing
  caller_tags: [finance] # Caller MUST have 'finance' tag
  target_tags: [billing] # Target MUST have 'billing' tag
  allow_functions: ["charge*_", "refund\__", "get*\*"]
  deny_functions: ["delete*_", "admin\__"]
  constraints:
  charge_customer:
  amount: <= 10000
  action: allow

# Policy 2: Support read-only

- name: support*readonly
  caller_tags: [support]
  target_tags: [customer-data]
  allow_functions: ["get*_", "query\__"]
  action: allow`

**This says:** "If caller has [finance] tag AND target has [billing] tag, then these functions are allowed"

---

### **Phase 2: Developer Builds Agent**

Developer writes code:

`# finance_bot.py
from agentfield import Agent

app = Agent(node_id="finance-bot-001")

@app.skill("charge_customer", tags=["finance", "payment"])
def charge_customer(customer_id: str, amount: float):
"""Charge customer's account""" # Business logic here
return {"status": "charged", "amount": amount}

@app.skill("get_balance", tags=["finance"])
def get_balance(customer_id: str):
"""Get customer balance"""
return {"balance": 1000.00}

app.serve()`

**Developer runs it:**

`$ python finance_bot.py`

**What happens:**

`Step 1: Agent generates DID (first run)
↓
Step 2: Agent sends registration to control plane:
{
"node_id": "finance-bot-001",
"did": "did:key:z6Mkf...",
"skills": [
{
"name": "charge_customer",
"proposed_tags": ["finance", "payment"] # ← Developer proposes
},
{
"name": "get_balance",
"proposed_tags": ["finance"]
}
]
}
↓
Step 3: Control plane checks tag approval rules

Looking at proposed_tags: ["finance", "payment"]

Check tag_rules.yaml: - "finance" → approval: manual ⏸️ - "payment" → (not in rules, defaults to manual) ⏸️

Result: PENDING_APPROVAL
↓
Step 4: Control plane stores agent with status = PENDING

Agent record:
{
"node_id": "finance-bot-001",
"did": "did:key:z6Mkf...",
"status": "pending_approval",
"proposed_tags": ["finance", "payment"],
"approved_tags": [], # Empty until admin approves
"skills": [...]
}
↓
Step 5: Agent terminal shows:

✅ Registered successfully
⏳ Waiting for admin approval
Proposed tags: [finance, payment]
Status: PENDING

⏸️ Agent paused until approved`

**Key point:** Developer **proposes** tags, but they're **NOT active** yet!

---

### **Phase 3: Admin Reviews & Approves**

Admin sees pending agent:

`$ agentfield admin pending

📋 Pending Approvals

Agent: finance-bot-001
DID: did:key:z6Mkf...
Proposed tags: [finance, payment]

Skills:
• charge_customer (tags: finance, payment)
• get_balance (tags: finance)

[a] Approve with proposed tags
[m] Modify tags
[r] Reject`

**Admin's options:**

### **Option A: Approve as-is**

`Choice: a

✅ Approving with tags: [finance, payment]
✅ Issuing PermissionVC to did:key:z6Mkf...
✅ Agent finance-bot-001 is now ACTIVE`

**Control plane creates PermissionVC:**

`{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "PermissionCredential"],
  "issuer": "did:agentfield:admin:server-root",
  "credentialSubject": {
    "id": "did:key:z6Mkf...",  // Agent's DID
    "permissions": {
      "tags": ["finance", "payment"],  // APPROVED tags
      "allowed_callees": ["*"]  // Can call anyone (policy decides)
    }
  },
  "expirationDate": "2026-03-06T10:30:00Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "proofValue": "..."  // Admin's signature
  }
}`

**Agent receives VC and activates:**

`# Agent terminal
⏳ Waiting for admin approval...

✅ Approved!
Tags: [finance, payment]
Expires: 30 days

🚀 Agent finance-bot-001 is ready!`

### **Option B: Modify tags**

`Choice: m

Current proposed tags: [finance, payment]
Enter approved tags (comma-separated): finance,internal

⚠️ Removing: payment
✅ Adding: internal
✅ Keeping: finance

Confirm? (yes/no): yes

✅ Issuing PermissionVC with tags: [finance, internal]`

**Result:** Agent gets [finance, internal], NOT [payment]

---

### **Phase 4: Agent Calls Another Agent**

Now agent tries to call billing service:

`# In finance_bot code
result = await app.call(
    target="billing-service.charge_customer",
    customer_id="C123456",
    amount=5000
)`

**What happens:**

`Step 1: SDK sends request to control plane
{
"caller_did": "did:key:z6Mkf...", // finance-bot-001
"target": "billing-service.charge_customer",
"input": {"customer_id": "C123456", "amount": 5000}
}
↓
Step 2: Control plane authorization check

2a. Load caller's PermissionVC
PermissionVC for did:key:z6Mkf...
Tags: [finance, internal]
Expires: 2026-03-06 ✅
Revoked: No ✅

2b. Verify PermissionVC signature
Issuer: did:agentfield:admin:server-root
Signature: Valid ✅

2c. Resolve target agent
"billing-service" → did:key:z6MkwQ...
Get billing-service's registration:
Tags: [billing, internal]

2d. Find matching policy
Looking for policy where:
caller_tags matches [finance, internal]
target_tags matches [billing, internal]
function matches "charge_customer"

      Found: finance_to_billing policy
        caller_tags: [finance] ✅ (caller has it)
        target_tags: [billing] ✅ (target has it)
        allow_functions: ["charge_*"] ✅ (matches)
        deny_functions: ["delete_*"] ✅ (not matched)

2e. Check constraints
Policy says: charge_customer.amount <= 10000
Input amount: 5000
5000 <= 10000 ✅

2f. DECISION: ALLOW ✅
↓
Step 3: Execute function on billing-service
↓
Step 4: Return result to finance-bot`

**If constraint violated:**

`# Trying to charge $15,000 (over limit)
result = await app.call(
    target="billing-service.charge_customer",
    customer_id="C123456",
    amount=15000  # Over $10k limit!
)`

`Step 2e: Check constraints
Policy says: charge_customer.amount <= 10000
Input amount: 15000
15000 <= 10000 ❌ VIOLATION

DECISION: DENY ❌`

**Agent gets error:**

`PermissionError: Constraint violation
  Policy: finance_to_billing
  Function: charge_customer
  Constraint: amount <= 10000
  Your input: amount = 15000`

---

## **Trust Boundaries: Where We Trust, Where We Don't**

### **❌ We DO NOT Trust: Developer**

### **Developer CANNOT:**

1. **Self-assign active tags**

    `@app.skill("hack", tags=["admin", "root"])  # Proposed only!`

    These tags are **proposed**, not active until admin approves.

2. **Bypass approval**

    Developer can't force their agent to be active without admin approval.

3. **Forge PermissionVC**

    `# Developer can't do this:
fake_vc = create_fake_permission_vc(tags=["admin"])`

    Control plane verifies **admin's signature** on VC. Developer doesn't have admin's private key.

4. **Call functions without matching policy**

    Even if developer tries to call admin functions, policy check will deny if tags don't match.

5. **Modify their PermissionVC**

    VC is signed by admin. Any modification breaks the signature → rejected.

6. **Claim another agent's DID**

    DID is tied to private key. Developer can't sign as another agent's DID without stealing that agent's private key file.

---

### **✅ We DO Trust: Admin**

### **Admin CAN:**

1. **Issue PermissionVCs**

    Admin controls who gets what tags.

2. **Define policies**

    Admin decides which tags can call which tags.

3. **Revoke permissions**

    Admin can instantly revoke any agent.

4. **Set constraints**

    Admin controls amount limits, function restrictions, etc.

**Why we trust admin:** Admin runs the control plane. If admin is compromised, the whole system is compromised anyway.

---

### **✅ We DO Trust: Control Plane**

### **Control Plane CAN:**

1. **Verify PermissionVC signatures**

    Control plane has admin's public key, verifies all VCs.

2. **Enforce policies**

    Control plane is the enforcement point.

3. **Store agent DIDs**

    Control plane maintains the DID registry.

**Why we trust control plane:** It's the central authority. Everything goes through it.

---

### **⚠️ We PARTIALLY Trust: Developer's Proposed Tags**

### **Developer proposes, Admin decides:**

`Developer says: "I want tags [finance, admin]"
↓
Control plane checks tag_rules:

- finance → manual approval
- admin → forbidden!
  ↓
  Admin sees: "Agent wants [finance, admin]"
  Admin thinks: "Hmm, why admin? That's suspicious"
  Admin approves: [finance] only
  ↓
  Agent gets: [finance]`

**We trust developer to:**

- Honestly describe what their agent does
- Propose reasonable tags
- Not try to trick the admin

**We DON'T trust developer to:**

- Actually get those tags without approval
- Bypass the admin

---

## **Comparison: What Developer Proposes vs What Agent Gets**

| **Developer Writes**                    | **Proposed Tags** | **Admin Approves** | **Agent Gets (Active)** | **Can Call**            |
| --------------------------------------- | ----------------- | ------------------ | ----------------------- | ----------------------- |
| `@app.skill(tags=["finance"])`          | [finance]         | [finance]          | [finance]               | billing services ✅     |
| `@app.skill(tags=["finance", "admin"])` | [finance, admin]  | [finance] only     | [finance]               | billing ✅, admin ❌    |
| `@app.skill(tags=["internal"])`         | [internal]        | [internal] (auto)  | [internal]              | limited access          |
| `@app.skill(tags=["superuser"])`        | [superuser]       | REJECTED           | [] (no tags)            | nothing (agent blocked) |

---

## **The Key Insight: Two-Step Authorization**

There are **TWO separate checks**:

### **Check 1: Tag Assignment (Admin Approval)**

`Question: Does this agent deserve these tags?
Who decides: Admin
When: At registration time
Result: PermissionVC with approved tags`

### **Check 2: Function Call (Policy Evaluation)**

`Question: Can caller's tags call target's function?
Who decides: Policy engine (automated)
When: Every function call
Result: Allow or Deny based on policies`

**Example:**

`Developer registers agent with tags: [finance, admin]
  ↓
Check 1: Admin approves only [finance]
  Agent's PermissionVC: tags = [finance]
  ↓
Developer tries: app.call("admin-panel.delete_all")
  ↓
Check 2: Policy evaluation
  Caller tags: [finance]
  Target tags: [admin]
  Policy: No rule matches
  Result: DENY ❌`

**Both checks must pass!**

---

## **Where Can Developer Cheat? (And Why It Doesn't Matter)**

### **Attempt 1: Claim Admin Tags**

`@app.skill("backdoor", tags=["admin", "root"])`

**Why it fails:**

- Admin sees proposed tags: [admin, root]
- Admin rejects or removes these tags
- Agent gets NO admin privileges

---

### **Attempt 2: Forge PermissionVC**

`# Developer tries to create fake VC
fake_vc = {
    "credentialSubject": {
        "id": "did:key:my-agent",
        "permissions": {"tags": ["admin"]}
    },
    "proof": {"proofValue": "fake-signature"}
}`

**Why it fails:**

- Control plane verifies signature
- Signature must be from admin's private key
- Developer doesn't have admin's private key
- Verification fails → rejected

---

### **Attempt 3: Modify Node ID to Match Pattern**

`# Developer knows pattern "finance-*" gets auto-approved
app = Agent(node_id="finance-sneaky-admin-bot")`

**Why it might work (if pattern-based auto-approval is too broad):**

- Pattern matches "finance-\*"
- Auto-assigned tags: [finance]
- **But**: Only gets [finance] tags, not [admin]
- Still can't call admin functions (policy blocks it)

**How to prevent:**

- Use manual approval instead of auto-approval
- Or use more specific patterns

---

### **Attempt 4: Call Admin Function Directly**

`# Developer tries to call admin function
result = await app.call("admin-panel.delete_all_data")`

**Why it fails:**

- Control plane checks policy
- Caller tags: [finance]
- Target tags: [admin]
- No policy matches
- Result: DENY ❌

---

## **The Bottom Line**

**We trust developers to:**

- Write correct business logic
- Not introduce bugs
- Propose honest tags

**We DON'T trust developers to:**

- Assign their own active permissions (admin does this)
- Bypass policies (control plane enforces)
- Forge credentials (cryptographic signatures prevent this)

**The security model is:**

1. **Developer proposes** → "I want tags [finance]"
2. **Admin approves** → "Okay, you can have [finance]"
3. **Control plane enforces** → "Caller has [finance], policy allows this call"

**All three must align for access to work.**

Does this clarify the flow and trust boundaries?

**Control plane needed only for**:

- ✅ Issuing new VCs
- ✅ Publishing revocation lists (agents cache it)
- ✅ Serving admin public keys
- ✅ Serving policy updates

**NOT needed for**: Real-time authorization of every call

Agents verify independently using:

- Admin public keys (fetched on startup)
- Policies (fetched every 5 minutes)
- Revocation list (fetched every 5 minutes)

**This gives you**:

- ✅ Low latency (local verification)
- ✅ Horizontal scaling (no central bottleneck)
- ✅ Resilience (survives control plane outage for 5+ minutes)
- ✅ Eventual consistency (good enough for most use cases)
