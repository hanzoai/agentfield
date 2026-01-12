# Notification Intelligence - Multi-Agent Architecture

## Philosophy: Autonomous Software as Backend Intelligence

This agent demonstrates **guided autonomy** - a multi-reasoner system where:
- AI makes strategic decisions within bounded domains
- Multiple specialists run in parallel and synthesize results
- System adapts reasoning depth based on data quality
- Intelligence emerges from composition, not individual models

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    ORCHESTRATION LAYER                       │
│  (Main Reasoners - Visible in Workflow UI)                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  learn_from_feedback          decide_notification_strategy  │
│         │                                  │                 │
│         ├── Parallel ──────────────────────┤                │
│         │                                  │                 │
│    ┌────┴────┐                        ┌───┴────┐           │
│    │ Intent  │                        │Decision│           │
│    │Extract  │                        │Analysis│           │
│    └────┬────┘                        └───┬────┘           │
└─────────┼───────────────────────────────────┼───────────────┘
          │                                    │
┌─────────┼────────────────────────────────────┼───────────────┐
│         │      SPECIALIST REASONERS          │               │
│         │      (Parallel Execution)          │               │
├─────────┼────────────────────────────────────┼───────────────┤
│         │                                    │               │
│    ┌────▼────────┬────────────┬─────────┐   │               │
│    │ Importance  │  Action    │ Channel │   │               │
│    │ Intent      │  Intent    │ Intent  │   │               │
│    └─────────────┴────────────┴─────────┘   │               │
│              │                               │               │
│         ┌────▼─────┐                    ┌────▼────────────┐ │
│         │Synthesize│                    │  Urgency        │ │
│         │ Insights │                    │  Analysis       │ │
│         └──────────┘                    ├─────────────────┤ │
│                                         │  Channel        │ │
│                                         │  Analysis       │ │
│                                         ├─────────────────┤ │
│                                         │  Timing         │ │
│                                         │  Analysis       │ │
│                                         └────┬────────────┘ │
│                                              │              │
│                                         ┌────▼──────┐      │
│                                         │Synthesize │      │
│                                         │ Decision  │      │
│                                         └───────────┘      │
└────────────────────────────────────────────────────────────┘
```

## Reasoner Hierarchy

### **Level 1: Orchestrators** (User-facing endpoints)

These are called by external systems via HTTP API.

#### `learn_from_feedback`
**Purpose:** Learn from user's interaction with a notification

**Workflow:**
```
1. Fetch user model from ACTOR memory
2. Call 3 specialist reasoners in PARALLEL:
   - extract_importance_intent
   - extract_action_intent
   - extract_channel_intent
3. Call synthesize_feedback_insights (combines results)
4. Update user model in ACTOR memory
5. Return insights discovered
```

**Cost:** 4 AI calls (3 parallel + 1 synthesis)

#### `decide_notification_strategy`
**Purpose:** Recommend how to handle a new notification

**Adaptive Routing:**
- **Fast Path** (sample_size > 10): 1 AI call with learned model
- **Deep Path** (sample_size ≤ 10): 4 AI calls in sequence:
  1. analyze_urgency + analyze_channel (parallel)
  2. analyze_timing (uses urgency results)
  3. synthesize_decision (combines all)

**Cost:** 1 AI call (fast) or 4 AI calls (deep)

### **Level 2: Specialist Reasoners** (Focused analysis)

Each specialist reasons within a **narrow domain** for precision.

#### Intent Extraction Specialists

**`extract_importance_intent`**
- Analyzes WHY user rated notification at specific importance
- Returns: priority category, mental model, implicit preferences

**`extract_action_intent`**
- Analyzes WHY user took action (opened/dismissed/ignored)
- Returns: behavior signal, timing quality, engagement reason

**`extract_channel_intent`**
- Analyzes channel effectiveness from user response
- Returns: effectiveness rating, numerical score, recommendation

**`synthesize_feedback_insights`**
- Combines all intent analyses into unified insights
- Returns: patterns discovered, preference updates, confidence

#### Decision Analysis Specialists

**`analyze_urgency`**
- Focuses ONLY on how urgent notification is
- Returns: priority score (0-100), time sensitivity, can_wait flag

**`analyze_channel`**
- Focuses ONLY on which channel to use
- Returns: best channel, reasoning, backup option

**`analyze_timing`**
- Focuses ONLY on when to send
- Returns: timing decision (immediate/delay/batch), delay_until, reasoning

**`synthesize_decision`**
- Combines urgency + channel + timing into final recommendation
- Returns: action, priority, channel, timing, comprehensive reasoning

## Memory Architecture

### ACTOR Scope (Per-User Models)

```python
# Stored at: actor_mem.set("preference_model", ...)
# Scope: router.memory.actor(user_id)

{
  "notification_preferences": {
    "payment_failed": "critical",
    "order_shipped": "high",
    "marketing": "low"
  },
  "channel_effectiveness": {
    "email": 0.3,    # 30% engagement
    "sms": 0.8,      # 80% engagement
    "push": 0.6,     # 60% engagement
    "in-app": 0.0    # Not tested yet
  },
  "timing_patterns": {
    "best_hours": [9, 10, 14, 19],
    "quiet_hours": [22, 23, 0, 1, 2, 3, 4, 5, 6, 7]
  },
  "sample_size": 15  # Number of feedback samples
}
```

### Learning Loop

```
User interacts → Feedback → Intent extraction (parallel) →
Synthesis → Update model → Better decisions next time
```

## Guided Autonomy Principles

###1. **Bounded Reasoning**
Each specialist has a **narrow focus** (urgency OR channel OR timing).
- Prevents hallucination
- Improves accuracy
- Enables parallelization

### 2. **Adaptive Depth**
System **decides HOW to reason** based on data quality:
- **High confidence** (>10 samples): Fast path, trust the model
- **Low confidence** (≤10 samples): Deep path, multi-specialist analysis

### 3. **Parallel Composition**
Independent analyses run **simultaneously**:
- Intent extraction: 3 specialists in parallel
- Decision analysis: urgency + channel in parallel
- **Reduces latency** while maintaining quality

### 4. **Synthesis Over Single Shot**
Never ask one LLM to do everything:
- Specialists analyze their domain
- **Orchestrator synthesizes** results
- Emergent intelligence from composition

## Cost Analysis

### Per Notification Decision

**New User (sample_size = 0):**
```
Deep Path:
- analyze_urgency: 1 call
- analyze_channel: 1 call (parallel with urgency)
- analyze_timing: 1 call
- synthesize_decision: 1 call
Total: 4 AI calls
```

**Experienced User (sample_size > 10):**
```
Fast Path:
- Single reasoner with learned model: 1 call
Total: 1 AI call
```

**Cost reduction:** 75% after learning phase!

### Per Feedback Learning

```
Intent extraction (always):
- extract_importance_intent: 1 call
- extract_action_intent: 1 call (parallel)
- extract_channel_intent: 1 call (parallel)
- synthesize_feedback_insights: 1 call
Total: 4 AI calls
```

**Amortized cost:** Each feedback improves all future decisions.

## Production Backend Features

### 1. **Batch Feedback Processing**
```python
# Process 100 users' feedback in parallel
await app.call("notification-intelligence.process_feedback_batch",
  feedback_items=[...])
```

### 2. **Notification Queue Optimization**
```python
# Reorder/group pending notifications intelligently
await app.call("notification-intelligence.optimize_notification_queue",
  pending_notifications=[...])
```

### 3. **User Segmentation Analysis**
```python
# Discover user segments by behavior
await app.call("notification-intelligence.analyze_user_segments",
  user_ids=[...])
```

### 4. **Temporal Pattern Analysis**
```python
# Find optimal send times across population
await app.call("notification-intelligence.analyze_optimal_times",
  historical_data=[...])
```

## Observability

Every reasoner creates **notes** visible in AgentField UI:
- Which path was taken (fast vs deep)
- Parallel execution indicators
- Synthesis reasoning
- Model updates

**Workflow DAG shows:**
- Orchestrator → Specialist calls
- Parallel execution branches
- Synthesis points
- Memory reads/writes

## Key Differentiators

**vs. Rule-Based Systems:**
- ✅ Handles edge cases gracefully
- ✅ Adapts to user preferences implicitly
- ✅ Improves over time without code changes

**vs. Single-LLM Approaches:**
- ✅ More accurate (specialists > generalist)
- ✅ Faster (parallelization)
- ✅ Cheaper (fast path after learning)
- ✅ Observable (workflow graph)

**vs. Traditional ML:**
- ✅ No training data needed upfront
- ✅ Explainable (reasoning in plain English)
- ✅ Zero-shot works, improves with feedback
- ✅ Handles novel situations

## Scalability

**Horizontal:**
- Each reasoner is stateless
- Parallel execution across users
- Control plane handles routing

**Vertical:**
- Fast path reduces cost 75%
- Batch operations amortize overhead
- Memory queries are O(1)

**Cost-Effective:**
- New users: 4-5 calls per decision
- After 10 samples: 1 call per decision
- Self-optimizing system

## Use Cases

This architecture works for any domain needing **intelligent decision-making**:

- **E-commerce:** Product recommendations, pricing optimization
- **Healthcare:** Patient triage, treatment suggestions
- **Finance:** Fraud detection, risk assessment
- **SaaS:** Feature recommendations, churn prevention
- **Logistics:** Route optimization, delivery scheduling

**The pattern is universal:** Multiple specialists → Parallel execution → Synthesis
