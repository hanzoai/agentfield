# PRD: Policy Engine for AgentField

**Version:** 1.0
**Status:** Draft
**Author:** Santosh Kumar Radha
**Date:** January 2025

---

## Executive Summary

This document specifies a tag-based policy engine for AgentField that enables fine-grained authorization control over agent interactions. The system leverages the existing DID (Decentralized Identifier) infrastructure to provide cryptographically-verifiable policy decisions while exposing a simple, intuitive developer experience based on tags.

**Core Philosophy:** Developers write tags. Admins write YAML. The system enforces cryptographically.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Goals and Non-Goals](#goals-and-non-goals)
3. [Architecture Overview](#architecture-overview)
4. [Data Model](#data-model)
5. [Policy Language Specification](#policy-language-specification)
6. [Evaluation Engine](#evaluation-engine)
7. [Developer Experience](#developer-experience)
8. [REST API Specification](#rest-api-specification)
9. [Integration Points](#integration-points)
10. [Security Considerations](#security-considerations)
11. [Implementation Phases](#implementation-phases)
12. [Success Metrics](#success-metrics)

---

## Problem Statement

### Current State

AgentField provides robust infrastructure for multi-agent systems:
- **Identity:** Every agent, reasoner, and skill has a cryptographic DID
- **Audit:** Verifiable Credentials (VCs) prove execution provenance
- **Discovery:** Agents can discover and call other agents
- **Memory:** Scoped memory with workflow/session/global levels

### Gap

There is no authorization layer between identity and action:
- Any agent can call any other agent's reasoners
- No input-based constraints (e.g., "only managers can approve refunds > $1000")
- Memory access is scope-based but not role-based
- Discovery shows all agents to all agents (no visibility control)
- Policy logic is scattered in application code, not centrally auditable

### Impact

- **Security:** No defense-in-depth for sensitive operations
- **Compliance:** Cannot enforce regulatory requirements declaratively
- **Operations:** Cannot answer "who can do what?" without code review
- **Multi-tenancy:** Cannot isolate tenants at the infrastructure level

---

## Goals and Non-Goals

### Goals

1. **Zero-boilerplate authorization** — Developers use existing tags; no new concepts
2. **Declarative policy** — YAML configuration, not code
3. **Input-aware constraints** — Policies can reference call parameters
4. **Cryptographic audit trail** — Every decision becomes a verifiable credential
5. **Central enforcement** — Control plane enforces; SDKs don't need changes
6. **Fail-closed default** — If no rule explicitly allows, access is denied
7. **Queryable policies** — "Who can call X?" is an API call, not a code review

### Non-Goals

1. **Complex policy language** — No Rego, Datalog, or custom DSL
2. **SDK-side enforcement** — All enforcement happens in control plane
3. **Real-time policy updates during execution** — Policies are evaluated at call-time
4. **Hierarchical roles** — Flat tag-based model, not RBAC trees
5. **External policy service** — Embedded in Go binary, not separate infrastructure

---

## Architecture Overview

### System Context

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Control Plane (Go)                          │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │ DID Service │    │ VC Service  │    │    Policy Engine        │ │
│  │             │◄───│             │◄───│                         │ │
│  │ - Identity  │    │ - Audit     │    │ - Rule storage          │ │
│  │ - Keys      │    │ - Proofs    │    │ - Tag resolution        │ │
│  │             │    │             │    │ - Evaluation            │ │
│  └─────────────┘    └─────────────┘    │ - Decision logging      │ │
│         │                  │           └───────────┬─────────────┘ │
│         │                  │                       │               │
│         ▼                  ▼                       ▼               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Execution Handler                         │   │
│  │                                                              │   │
│  │   1. Receive call request                                   │   │
│  │   2. Resolve caller/target DIDs → tags                      │   │
│  │   3. Evaluate policy rules                                  │   │
│  │   4. If allowed: forward to agent                           │   │
│  │   5. If denied: return error + create audit VC              │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              ┌─────────┐    ┌─────────┐    ┌─────────┐
              │ Agent A │    │ Agent B │    │ Agent C │
              │ Python  │    │   Go    │    │   TS    │
              │         │    │         │    │         │
              │ Tags:   │    │ Tags:   │    │ Tags:   │
              │[finance]│    │[support]│    │ [admin] │
              └─────────┘    └─────────┘    └─────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Policy primitive | Tags | Developers already use tags; zero learning curve |
| Policy format | YAML | Human-readable, version-controllable, auditable |
| Enforcement point | Control plane | Single point of enforcement; SDK-agnostic |
| Identity binding | DIDs | Cryptographic proof without developer effort |
| Default stance | Deny | Security by default; explicit allow required |
| Audit mechanism | VCs | Leverages existing infrastructure; tamper-proof |

---

## Data Model

### Core Types

```go
// PolicyRule represents a single authorization rule
type PolicyRule struct {
    ID          string            `json:"id" db:"id"`
    Name        string            `json:"name" db:"name"`
    Description string            `json:"description,omitempty" db:"description"`
    Type        PolicyRuleType    `json:"type" db:"type"`
    Priority    int               `json:"priority" db:"priority"`
    Enabled     bool              `json:"enabled" db:"enabled"`

    // Source matching
    FromTags    []string          `json:"from_tags" db:"from_tags"`
    FromAgents  []string          `json:"from_agents,omitempty" db:"from_agents"`

    // Target matching
    ToTags      []string          `json:"to_tags" db:"to_tags"`
    ToAgents    []string          `json:"to_agents,omitempty" db:"to_agents"`
    Target      string            `json:"target,omitempty" db:"target"` // Pattern: "agent.reasoner"

    // Action
    Effect      PolicyEffect      `json:"effect" db:"effect"` // allow, deny

    // Conditions (for input-aware policies)
    Conditions  []PolicyCondition `json:"conditions,omitempty" db:"conditions"`

    // Metadata
    CreatedAt   time.Time         `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
    CreatedBy   string            `json:"created_by,omitempty" db:"created_by"`
}

type PolicyRuleType string
const (
    PolicyRuleTypeAccess    PolicyRuleType = "access"     // Cross-agent call authorization
    PolicyRuleTypeMemory    PolicyRuleType = "memory"     // Memory scope access
    PolicyRuleTypeDiscovery PolicyRuleType = "discovery"  // Agent visibility
)

type PolicyEffect string
const (
    PolicyEffectAllow PolicyEffect = "allow"
    PolicyEffectDeny  PolicyEffect = "deny"
)

// PolicyCondition represents an input-based condition
type PolicyCondition struct {
    Expression    string   `json:"expression"`              // e.g., "input.amount > 1000"
    RequireTags   []string `json:"require_tags,omitempty"`  // Additional tags required
    Effect        PolicyEffect `json:"effect,omitempty"`    // Override effect if condition matches
    Message       string   `json:"message,omitempty"`       // Custom denial message
}

// PolicyDecision represents the outcome of a policy evaluation
type PolicyDecision struct {
    ID            string            `json:"id"`
    Allowed       bool              `json:"allowed"`
    Effect        PolicyEffect      `json:"effect"`

    // Context
    CallerDID     string            `json:"caller_did"`
    CallerTags    []string          `json:"caller_tags"`
    TargetDID     string            `json:"target_did"`
    TargetTags    []string          `json:"target_tags"`
    Target        string            `json:"target"`         // "agent.reasoner"
    Input         json.RawMessage   `json:"input,omitempty"`

    // Decision details
    RuleID        string            `json:"rule_id,omitempty"`
    RuleName      string            `json:"rule_name,omitempty"`
    Reason        string            `json:"reason"`

    // Suggestions (on denial)
    Suggestions   []PolicySuggestion `json:"suggestions,omitempty"`

    // Audit
    Timestamp     time.Time         `json:"timestamp"`
    ExecutionID   string            `json:"execution_id,omitempty"`
    WorkflowID    string            `json:"workflow_id,omitempty"`
}

type PolicySuggestion struct {
    AgentID string   `json:"agent_id"`
    Tags    []string `json:"tags"`
    Reason  string   `json:"reason"`
}

// TagMapping associates DIDs with tags for fast lookup
type TagMapping struct {
    DID         string    `json:"did" db:"did"`
    EntityType  string    `json:"entity_type" db:"entity_type"` // agent, reasoner, skill
    EntityID    string    `json:"entity_id" db:"entity_id"`
    Tags        []string  `json:"tags" db:"tags"`
    AgentNodeID string    `json:"agent_node_id" db:"agent_node_id"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
```

### Database Schema

```sql
-- Policy rules table
CREATE TABLE policy_rules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    type            TEXT NOT NULL CHECK (type IN ('access', 'memory', 'discovery')),
    priority        INTEGER NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    from_tags       JSONB NOT NULL DEFAULT '[]',
    from_agents     JSONB DEFAULT '[]',
    to_tags         JSONB NOT NULL DEFAULT '[]',
    to_agents       JSONB DEFAULT '[]',
    target          TEXT,
    effect          TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    conditions      JSONB DEFAULT '[]',
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by      TEXT
);

CREATE INDEX idx_policy_rules_type ON policy_rules(type);
CREATE INDEX idx_policy_rules_enabled ON policy_rules(enabled);
CREATE INDEX idx_policy_rules_priority ON policy_rules(priority DESC);

-- Tag mappings for fast DID → tags lookup
CREATE TABLE tag_mappings (
    did             TEXT PRIMARY KEY,
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('agent', 'reasoner', 'skill')),
    entity_id       TEXT NOT NULL,
    tags            JSONB NOT NULL DEFAULT '[]',
    agent_node_id   TEXT NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tag_mappings_agent_node ON tag_mappings(agent_node_id);
CREATE INDEX idx_tag_mappings_tags ON tag_mappings USING GIN(tags);

-- Policy decisions audit log
CREATE TABLE policy_decisions (
    id              TEXT PRIMARY KEY,
    allowed         BOOLEAN NOT NULL,
    effect          TEXT NOT NULL,
    caller_did      TEXT NOT NULL,
    caller_tags     JSONB NOT NULL,
    target_did      TEXT NOT NULL,
    target_tags     JSONB NOT NULL,
    target          TEXT NOT NULL,
    input_hash      TEXT,
    rule_id         TEXT,
    rule_name       TEXT,
    reason          TEXT NOT NULL,
    execution_id    TEXT,
    workflow_id     TEXT,
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_decisions_caller ON policy_decisions(caller_did);
CREATE INDEX idx_policy_decisions_target ON policy_decisions(target_did);
CREATE INDEX idx_policy_decisions_allowed ON policy_decisions(allowed);
CREATE INDEX idx_policy_decisions_timestamp ON policy_decisions(timestamp DESC);
```

---

## Policy Language Specification

### YAML Configuration Format

Policies are defined in `agentfield.yaml` under the `policy` key:

```yaml
policy:
  # Default behavior when no rules match
  default: deny  # or "allow" (not recommended)

  # Access rules: who can call what
  access:
    - name: public-endpoints
      description: Anyone can call public reasoners
      allow:
        from: ["*"]           # Wildcard: any caller
        to: ["public"]        # Target must have "public" tag

    - name: finance-internal
      description: Finance team can access internal finance endpoints
      allow:
        from: ["finance"]     # Caller must have "finance" tag
        to: ["finance", "internal"]

    - name: admin-override
      description: Admins can call anything
      allow:
        from: ["admin"]
        to: ["*"]

    - name: block-deprecated
      description: Block calls to deprecated endpoints
      deny:
        from: ["*"]
        to: ["deprecated"]

  # Constraints: input-aware rules for specific targets
  constraints:
    # Pattern matches agent.reasoner or just reasoner name
    "*.approve_refund":
      - require_tags: ["finance"]
        message: "Refund approval requires finance authorization"

      - when: "input.amount > 1000"
        require_tags: ["manager"]
        message: "Refunds over $1000 require manager approval"

      - when: "input.amount > 10000"
        deny: true
        message: "Use approve_large_refund for amounts over $10,000"

    "billing-service.charge":
      - require_tags: ["billing", "pci-compliant"]

      - when: "input.amount > 50000"
        require_second_approval:
          from_tags: ["executive"]
          via_field: "approver_did"

  # Memory access rules
  memory:
    - scope: "pii.*"
      description: PII data requires authorization
      require_tags: ["pii-authorized"]

    - scope: "payment.*"
      require_tags: ["pci-compliant"]

    - scope: "global.*"
      allow: ["*"]

  # Discovery rules: who can see whom
  discovery:
    default: same-tags  # Agents see others with at least one overlapping tag

    rules:
      - name: public-visibility
        allow:
          from: ["*"]
          see: ["public"]

      - name: admin-sees-all
        allow:
          from: ["admin"]
          see: ["*"]
```

### Tag Matching Semantics

**Wildcard (`*`):**
- `from: ["*"]` — matches any caller
- `to: ["*"]` — matches any target

**Single tag:**
- `from: ["finance"]` — caller must have "finance" tag

**Multiple tags (OR logic):**
- `from: ["finance", "admin"]` — caller must have "finance" OR "admin"

**All-of (AND logic):**
- `require_tags: ["finance", "manager"]` — caller must have BOTH tags

**Negation:**
- `from: ["!external"]` — caller must NOT have "external" tag

### Condition Expression Language

Conditions use a simple expression language for input validation:

```
# Comparison operators
input.amount > 1000
input.amount >= 1000
input.amount < 1000
input.amount <= 1000
input.amount == 1000
input.amount != 1000

# String operations
input.region == "us-west"
input.category in ["premium", "enterprise"]
input.email contains "@company.com"
input.name startswith "admin_"

# Boolean logic
input.amount > 1000 and input.priority == "high"
input.amount > 10000 or input.override == true

# Nested fields
input.customer.tier == "enterprise"
input.metadata.tags contains "urgent"

# Null checks
input.approver != null
input.optional exists
```

---

## Evaluation Engine

### Evaluation Algorithm

```go
func (e *PolicyEngine) Evaluate(ctx *EvaluationContext) (*PolicyDecision, error) {
    // 1. Resolve caller tags from DID
    callerTags, err := e.resolveTags(ctx.CallerDID)
    if err != nil {
        return deny("Failed to resolve caller identity"), nil
    }

    // 2. Resolve target tags from DID
    targetTags, err := e.resolveTags(ctx.TargetDID)
    if err != nil {
        return deny("Failed to resolve target identity"), nil
    }

    // 3. Load applicable rules (sorted by priority)
    rules := e.loadRules(ctx.RuleType)

    // 4. Evaluate rules in priority order
    for _, rule := range rules {
        if !rule.Enabled {
            continue
        }

        // Check if rule applies to this caller/target
        if !e.matchesTags(callerTags, rule.FromTags) {
            continue
        }
        if !e.matchesTags(targetTags, rule.ToTags) {
            continue
        }
        if rule.Target != "" && !e.matchesTarget(ctx.Target, rule.Target) {
            continue
        }

        // Evaluate conditions
        conditionResult := e.evaluateConditions(rule.Conditions, ctx.Input, callerTags)

        // Apply effect
        if conditionResult.Override != nil {
            return e.buildDecision(ctx, rule, *conditionResult.Override, conditionResult.Message)
        }

        return e.buildDecision(ctx, rule, rule.Effect, "")
    }

    // 5. No rule matched — apply default
    return e.buildDecision(ctx, nil, e.defaultEffect, "No matching policy rule")
}
```

### Tag Resolution

Tags are resolved through the DID → tag mapping:

```go
func (e *PolicyEngine) resolveTags(did string) ([]string, error) {
    // Check cache first
    if cached, ok := e.tagCache.Get(did); ok {
        return cached.([]string), nil
    }

    // Load from storage
    mapping, err := e.storage.GetTagMapping(did)
    if err != nil {
        return nil, err
    }

    // Cache for future lookups
    e.tagCache.Set(did, mapping.Tags, 5*time.Minute)

    return mapping.Tags, nil
}
```

### Condition Evaluation

```go
type ConditionEvaluator struct {
    // Expression parser for simple conditions
}

func (ce *ConditionEvaluator) Evaluate(condition PolicyCondition, input map[string]any, callerTags []string) ConditionResult {
    // Parse and evaluate expression
    if condition.Expression != "" {
        matches, err := ce.evaluateExpression(condition.Expression, input)
        if err != nil || !matches {
            return ConditionResult{Matched: false}
        }
    }

    // Check required tags
    if len(condition.RequireTags) > 0 {
        if !hasAllTags(callerTags, condition.RequireTags) {
            return ConditionResult{
                Matched: true,
                Override: ptr(PolicyEffectDeny),
                Message:  condition.Message,
            }
        }
    }

    // Check for explicit effect override
    if condition.Effect != "" {
        return ConditionResult{
            Matched:  true,
            Override: &condition.Effect,
            Message:  condition.Message,
        }
    }

    return ConditionResult{Matched: true}
}
```

---

## Developer Experience

### Python SDK

No changes required for basic usage. Tags are already supported:

```python
from agentfield import Agent

# Tags defined at agent level
app = Agent(
    node_id="finance-bot",
    tags=["finance", "pci-compliant"]
)

# Tags defined at reasoner level
@app.reasoner(tags=["internal", "high-value"])
async def approve_refund(amount: float, reason: str) -> dict:
    # If execution reaches here, policy already approved
    return {"approved": True, "amount": amount}
```

**Optional policy API** (for dynamic cases):

```python
@app.reasoner()
async def check_and_route(request: dict) -> dict:
    # Check if current caller can perform an action
    can_approve = await app.policy.check(
        action="call",
        target="billing.charge",
        context={"amount": request["amount"]}
    )

    if not can_approve.allowed:
        # Find who can perform this action
        approvers = await app.policy.who_can(
            action="call",
            target="billing.charge",
            context={"amount": request["amount"]}
        )
        return {
            "status": "needs_approval",
            "reason": can_approve.reason,
            "approvers": [a.agent_id for a in approvers]
        }

    return await app.call("billing.charge", input=request)
```

### TypeScript SDK

```typescript
import { Agent } from '@agentfield/sdk';

const app = new Agent({
  nodeId: 'finance-bot',
  tags: ['finance', 'pci-compliant']
});

app.reasoner('approve_refund', {
  tags: ['internal', 'high-value']
}, async (ctx, input: { amount: number; reason: string }) => {
  return { approved: true, amount: input.amount };
});

// Optional policy API
app.reasoner('check_and_route', async (ctx, input) => {
  const canApprove = await ctx.policy.check({
    action: 'call',
    target: 'billing.charge',
    context: { amount: input.amount }
  });

  if (!canApprove.allowed) {
    const approvers = await ctx.policy.whoCan({
      action: 'call',
      target: 'billing.charge',
      context: { amount: input.amount }
    });
    return { status: 'needs_approval', approvers };
  }

  return ctx.call('billing.charge', input);
});
```

### Go SDK

```go
agent := agentfield.NewAgent(agentfield.Config{
    NodeID: "finance-bot",
    Tags:   []string{"finance", "pci-compliant"},
})

agent.RegisterReasoner("approve_refund", agentfield.ReasonerConfig{
    Tags: []string{"internal", "high-value"},
}, func(ctx *agentfield.Context, input ApproveRefundInput) (*ApproveRefundOutput, error) {
    return &ApproveRefundOutput{Approved: true, Amount: input.Amount}, nil
})
```

---

## REST API Specification

### Policy Rule Management

```yaml
# Create a policy rule
POST /api/v1/policy/rules
Content-Type: application/json

{
  "name": "finance-internal-access",
  "description": "Finance team can access internal endpoints",
  "type": "access",
  "priority": 100,
  "from_tags": ["finance"],
  "to_tags": ["internal"],
  "effect": "allow"
}

Response: 201 Created
{
  "id": "rule_abc123",
  "name": "finance-internal-access",
  ...
}

# List all policy rules
GET /api/v1/policy/rules?type=access&enabled=true

Response: 200 OK
{
  "rules": [...],
  "total": 15
}

# Get a specific rule
GET /api/v1/policy/rules/{id}

# Update a rule
PUT /api/v1/policy/rules/{id}

# Delete a rule
DELETE /api/v1/policy/rules/{id}

# Bulk import from YAML
POST /api/v1/policy/import
Content-Type: application/x-yaml

policy:
  access:
    - name: public-endpoints
      ...
```

### Policy Evaluation

```yaml
# Evaluate a policy (for debugging/testing)
POST /api/v1/policy/evaluate
Content-Type: application/json

{
  "caller": "finance-bot",        # Agent ID or DID
  "target": "billing.charge",     # Target pattern
  "input": {                      # Optional: input for condition evaluation
    "amount": 5000
  }
}

Response: 200 OK
{
  "allowed": false,
  "effect": "deny",
  "reason": "Caller requires tag: manager",
  "rule_id": "constraint-billing-charge-1",
  "caller_tags": ["finance"],
  "target_tags": ["billing", "internal"],
  "suggestions": [
    {
      "agent_id": "finance-manager-bot",
      "tags": ["finance", "manager"],
      "reason": "Has required manager tag"
    }
  ]
}

# "Who can" query
GET /api/v1/policy/who-can?action=call&target=billing.charge&amount=5000

Response: 200 OK
{
  "agents": [
    {"id": "finance-manager-bot", "tags": ["finance", "manager"]},
    {"id": "admin-bot", "tags": ["admin"]}
  ],
  "count": 2
}

# "What can" query (what can this agent do)
GET /api/v1/policy/what-can?agent=finance-bot

Response: 200 OK
{
  "capabilities": [
    {"target": "finance.*", "effect": "allow"},
    {"target": "billing.query", "effect": "allow"},
    {"target": "billing.charge", "effect": "deny", "reason": "Requires manager tag"}
  ]
}
```

### Policy Decisions Audit

```yaml
# Get policy decision history
GET /api/v1/policy/decisions?caller_did=did:key:abc&limit=100

Response: 200 OK
{
  "decisions": [
    {
      "id": "dec_xyz",
      "allowed": true,
      "caller_did": "did:key:abc",
      "target": "finance.approve_refund",
      "rule_id": "rule_123",
      "timestamp": "2025-01-15T10:30:00Z"
    },
    ...
  ],
  "total": 150
}

# Get decision as verifiable credential
GET /api/v1/policy/decisions/{id}/vc

Response: 200 OK
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "PolicyDecisionCredential"],
  "issuer": "did:key:agentfield-server",
  "credentialSubject": {
    "decision_id": "dec_xyz",
    "allowed": true,
    ...
  },
  "proof": {...}
}
```

---

## Integration Points

### Agent Registration

When an agent registers, tags are extracted and mapped:

```go
func (h *RegistrationHandler) HandleRegistration(req *RegistrationRequest) error {
    // ... existing registration logic ...

    // Extract and store tag mappings
    agentTags := req.Tags
    for _, reasoner := range req.Reasoners {
        reasonerDID := h.didService.GetReasonerDID(req.AgentNodeID, reasoner.ID)
        h.policyService.UpdateTagMapping(TagMapping{
            DID:         reasonerDID,
            EntityType:  "reasoner",
            EntityID:    reasoner.ID,
            Tags:        append(agentTags, reasoner.Tags...),
            AgentNodeID: req.AgentNodeID,
        })
    }

    return nil
}
```

### Execution Interception

Policy is checked before forwarding calls:

```go
func (h *ExecutionHandler) Execute(ctx *gin.Context) {
    // ... parse request ...

    // Policy check
    decision, err := h.policyEngine.Evaluate(&EvaluationContext{
        CallerDID:  ctx.GetHeader("X-Caller-DID"),
        TargetDID:  h.resolveTargetDID(target),
        Target:     target,
        Input:      input,
        RuleType:   PolicyRuleTypeAccess,
    })

    if err != nil {
        ctx.JSON(500, gin.H{"error": "Policy evaluation failed"})
        return
    }

    if !decision.Allowed {
        // Log decision as VC
        h.vcService.CreatePolicyDecisionVC(decision)

        ctx.JSON(403, gin.H{
            "error":       "Policy denied",
            "reason":      decision.Reason,
            "suggestions": decision.Suggestions,
        })
        return
    }

    // Proceed with execution
    h.forwardToAgent(ctx, target, input)
}
```

### Memory Access

Memory operations check policy before read/write:

```go
func (h *MemoryHandler) Get(ctx *gin.Context) {
    key := ctx.Query("key")

    // Policy check for memory access
    decision, err := h.policyEngine.Evaluate(&EvaluationContext{
        CallerDID: ctx.GetHeader("X-Caller-DID"),
        Target:    key,  // Memory key as target
        RuleType:  PolicyRuleTypeMemory,
    })

    if !decision.Allowed {
        ctx.JSON(403, gin.H{"error": "Memory access denied", "reason": decision.Reason})
        return
    }

    // Proceed with memory operation
    // ...
}
```

### Discovery Filtering

Discovery results are filtered based on policy:

```go
func (h *DiscoveryHandler) ListAgents(ctx *gin.Context) {
    callerDID := ctx.GetHeader("X-Caller-DID")
    allAgents := h.agentService.ListAgents()

    visibleAgents := []Agent{}
    for _, agent := range allAgents {
        decision, _ := h.policyEngine.Evaluate(&EvaluationContext{
            CallerDID: callerDID,
            TargetDID: agent.DID,
            RuleType:  PolicyRuleTypeDiscovery,
        })

        if decision.Allowed {
            visibleAgents = append(visibleAgents, agent)
        }
    }

    ctx.JSON(200, gin.H{"agents": visibleAgents})
}
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Policy bypass via direct agent call | All calls route through control plane |
| Tag spoofing | Tags are bound to DIDs; DIDs are cryptographic |
| Rule tampering | Policy decisions create VCs; tamper-evident |
| Privilege escalation | Fail-closed default; explicit allow required |
| Information disclosure via error messages | Generic errors for unauthorized callers |

### Audit Trail

Every policy decision creates an auditable record:

1. **Decision logged** — Caller, target, effect, rule, timestamp
2. **Optional VC** — Cryptographically signed credential
3. **Queryable** — "Show all denials in last 24h"
4. **Exportable** — For compliance reporting

### Defense in Depth

1. **Control plane enforcement** — Primary enforcement point
2. **SDK optional checks** — For early feedback (not security)
3. **VC verification** — Post-hoc audit capability
4. **Tag immutability** — Tags set at registration, not runtime

---

## Implementation Phases

### Phase 1: Core Engine (Week 1-2)

**Deliverables:**
- [ ] Data model and database schema
- [ ] PolicyRule CRUD operations
- [ ] Tag mapping storage and retrieval
- [ ] Basic evaluation engine (tag matching only)
- [ ] REST API for rule management
- [ ] Unit tests for evaluation logic

**Files to create/modify:**
- `internal/services/policy_service.go`
- `internal/storage/policy_storage.go`
- `internal/handlers/policy_handlers.go`
- `pkg/types/policy_types.go`
- `migrations/XXX_create_policy_tables.sql`

### Phase 2: Execution Integration (Week 2-3)

**Deliverables:**
- [ ] Tag extraction during agent registration
- [ ] Policy check in execution handler
- [ ] Policy check in memory handlers
- [ ] Discovery filtering
- [ ] Decision audit logging

**Files to modify:**
- `internal/handlers/registration.go`
- `internal/handlers/execute.go`
- `internal/handlers/memory.go`
- `internal/handlers/discovery.go`

### Phase 3: Condition Expressions (Week 3-4)

**Deliverables:**
- [ ] Expression parser for conditions
- [ ] Input-aware policy evaluation
- [ ] Constraint rules in YAML
- [ ] SDK policy check API (Python, TypeScript, Go)

**Files to create:**
- `internal/policy/expression_parser.go`
- `sdk/python/agentfield/policy.py`
- `sdk/typescript/src/policy.ts`
- `sdk/go/policy/policy.go`

### Phase 4: Advanced Features (Week 4-5)

**Deliverables:**
- [ ] Policy decision VCs
- [ ] "Who can" / "What can" queries
- [ ] YAML import/export
- [ ] UI for policy management (if applicable)
- [ ] Performance optimization (caching)

### Phase 5: Documentation & Testing (Week 5-6)

**Deliverables:**
- [ ] API documentation
- [ ] Developer guide
- [ ] Example policies for common scenarios
- [ ] Integration tests
- [ ] Load testing for policy evaluation

---

## Success Metrics

### Functional Metrics

- [ ] All cross-agent calls are policy-checked
- [ ] Memory access respects policy rules
- [ ] Discovery returns only visible agents
- [ ] Policy decisions are auditable

### Performance Metrics

- Policy evaluation < 5ms p99
- Tag resolution < 1ms (cached)
- No measurable latency increase for allowed calls

### Developer Experience Metrics

- Zero SDK code changes for basic usage
- Policy YAML is the only new artifact
- Policy errors include actionable suggestions

---

## Appendix A: Example Policies

### Financial Services

```yaml
policy:
  access:
    - name: public-api
      allow:
        from: ["*"]
        to: ["public"]

    - name: support-to-finance
      allow:
        from: ["support"]
        to: ["finance"]

    - name: finance-internal
      allow:
        from: ["finance"]
        to: ["finance", "internal"]

  constraints:
    "*.approve_refund":
      - require_tags: ["finance"]
      - when: "input.amount > 1000"
        require_tags: ["manager"]
      - when: "input.amount > 10000"
        deny: true
        message: "Use approve_large_refund for amounts > $10,000"
```

### Multi-Tenant SaaS

```yaml
policy:
  access:
    - name: tenant-isolation
      description: Agents can only call within same tenant
      allow:
        from: ["tenant:acme"]
        to: ["tenant:acme"]

    - name: shared-services
      description: System services are accessible to all
      allow:
        from: ["*"]
        to: ["system"]

  discovery:
    default: same-tags
    rules:
      - name: tenant-visibility
        allow:
          from: ["tenant:*"]
          see: ["tenant:$same", "system"]  # Same tenant + system
```

### Healthcare (HIPAA)

```yaml
policy:
  access:
    - name: phi-access
      description: PHI requires explicit authorization
      allow:
        from: ["hipaa-trained", "phi-authorized"]
        to: ["phi"]

    - name: clinical-staff
      allow:
        from: ["clinical"]
        to: ["clinical", "phi"]

  memory:
    - scope: "patient.*"
      require_tags: ["phi-authorized"]

    - scope: "analytics.*"
      require_tags: ["hipaa-trained"]  # De-identified data

  constraints:
    "*.access_patient_record":
      - require_tags: ["phi-authorized"]
      - when: "input.purpose not in ['treatment', 'payment', 'operations']"
        deny: true
        message: "Patient record access requires valid TPO purpose"
```

---

## Appendix B: Expression Language Grammar

```ebnf
expression     = comparison | logical_expr
logical_expr   = comparison (("and" | "or") comparison)*
comparison     = value comparator value
comparator     = "==" | "!=" | ">" | "<" | ">=" | "<=" | "in" | "contains" | "startswith"
value          = field_path | literal
field_path     = "input" ("." identifier)*
literal        = string | number | boolean | array
identifier     = [a-zA-Z_][a-zA-Z0-9_]*
string         = '"' [^"]* '"'
number         = [0-9]+ ("." [0-9]+)?
boolean        = "true" | "false"
array          = "[" (literal ("," literal)*)? "]"
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Tag** | A string label attached to an agent, reasoner, or skill |
| **DID** | Decentralized Identifier - cryptographic identity |
| **Policy Rule** | A declarative statement about what is allowed/denied |
| **Condition** | An input-aware expression that modifies rule behavior |
| **Effect** | The outcome of a rule: allow or deny |
| **Policy Decision** | The result of evaluating policy for a specific action |
| **Tag Mapping** | The association between a DID and its tags |

---

*End of PRD*
