# Adaptive Multi-Agent Notification Intelligence

**Visual multi-agent orchestration with self-improving AI reasoning**

This example demonstrates cutting-edge multi-agent patterns:
- **Parallel specialist reasoners** creating impressive workflow graphs
- **Adaptive orchestration** that evolves with learning
- **Meta-level intelligence** that optimizes itself
- **Production-ready** cost/quality optimization

## Architecture Highlights

### Visual Workflow Graphs

The system creates beautiful workflow visualizations in the AgentField UI:

**New User (Full Analysis):**
```
                    ┌─→ Urgency Specialist
                    ├─→ Channel Specialist
Route Notification ─┼─→ User State Specialist  ─→ Synthesis ─→ Decision
                    ├─→ Timing Specialist
                    └─→ Context Specialist
```
5 parallel specialists converging to synthesis (6 AI calls)

**Learning User (Moderate Analysis):**
```
                    ┌─→ Urgency Specialist
Route Notification ─┼─→ Channel Specialist ─→ Synthesis ─→ Decision
                    └─→ Timing Specialist
```
3 core specialists (4 AI calls, 33% cost reduction)

**Confident User (Streamlined):**
```
                    ┌─→ Urgency Specialist
Route Notification ─┼─→ Channel Specialist ─→ Quick Synthesis ─→ Decision
                    └
```
2 specialists only (3 AI calls, 50% cost reduction)

### Learning Graph

Separate workflow for continuous improvement:
```
                    ┌─→ Behavior Pattern Extractor
Learn from Feedback─┼─→ Channel Insight Extractor ─→ Store in Memory
                    └─→ Preference Signal Extractor
```
3 parallel learning specialists (3 AI calls)

## Quick Start (Docker)

The recommended way to run this example is with Docker Compose, which starts all services automatically.

### 1. Set Up Environment

```bash
# Copy the example env file
cp .env.example .env

# Edit .env and add your API key
# OPENROUTER_API_KEY=your_key_here
```

### 2. Start All Services

```bash
docker compose up
```

This starts:
- **Control Plane** at `http://localhost:8080` - AgentField workflow visualization
- **Agent** at `http://localhost:8001` - Notification intelligence agent
- **Demo API** at `http://localhost:8000` - FastAPI backend with WebSocket support
- **Frontend UI** at `http://localhost:3000` - Interactive demo interface

### 3. Open the Demo

Visit `http://localhost:3000` to use the interactive UI, or use the API directly.

---

## Manual Setup (Alternative)

If you prefer to run services manually without Docker:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables
```bash
export OPENAI_API_KEY="your-openai-key"
# OR use OpenRouter
export OPENROUTER_API_KEY="your-openrouter-key"
```

### 3. Start AgentField Control Plane
```bash
# Terminal 1
cd ../../control-plane
go run ./cmd/af dev
```

### 4. Start Agent
```bash
# Terminal 2
cd examples/notification-intelligence
python main.py
```

### 5. Start Demo API (Optional)
```bash
# Terminal 3
cd demo
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Start Frontend UI (Optional)
```bash
# Terminal 4
cd ui
npm install && npm run dev
```

Agent endpoints:
- Direct: `http://localhost:8001`
- Via control plane: `http://localhost:8080/api/v1/execute/notification-intelligence.*`

## Demo Scenarios

### Scenario 1: New User - Full 5-Specialist Analysis

**Context:** First time encountering this user. System uses ALL specialists for maximum insight.

**Expected Graph:** Beautiful 5-way parallel star pattern → synthesis node

```bash
# Step 1: First decision (impressive full analysis)
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_type": "payment_failed",
      "notification_data": {
        "amount": 149.99,
        "card_last4": "4242",
        "merchant": "Premium Service"
      },
      "context": {
        "user_timezone": "America/Los_Angeles",
        "current_time": "2025-01-24T14:30:00Z",
        "user_tier": "premium"
      }
    }
  }'
```

**What to observe in AgentField UI:**
- 5 parallel specialist nodes (urgency, channel, user state, timing, context)
- Each specialist's AI reasoning visible in notes
- Convergence to synthesis node
- Final decision with priority score
- `pattern_count: 0` → triggers full analysis

**Expected Output:**
```json
{
  "execution_id": "exec_xxx",
  "status": "succeeded",
  "result": {
    "decision": {
      "deliver": "now",
      "channel": "sms",
      "priority": 95,
      "reasoning": "High-priority payment failure requires immediate attention..."
    },
    "pattern_count": 0,
    "analysis_depth": "full"
  }
}
```

---

### Scenario 2: User Provides Feedback - Learning Graph

**Context:** User interacted with the notification. System learns from their behavior.

**Expected Graph:** 3 parallel learning specialists extracting insights

```bash
# Step 2: User opened notification quickly - teach the system
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.learn_from_feedback \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_id": "notif-001",
      "notification_type": "payment_failed",
      "user_response": {
        "action_taken": "opened",
        "time_to_action": 12,
        "importance_rating": 5,
        "channel_used": "sms"
      }
    }
  }'
```

**What to observe in AgentField UI:**
- Separate learning workflow graph
- 3 parallel insight extraction specialists
- Behavior, channel, and preference patterns extracted
- Storage to actor memory (user-specific)
- `sample_size` increments

**Expected Output:**
```json
{
  "result": {
    "patterns_learned": 3,
    "sample_size": 1,
    "insights": [
      {
        "pattern": "User responds urgently to payment failures",
        "strength": 0.9,
        "applies_to": "payment_failed"
      },
      {
        "pattern": "SMS highly effective for this user",
        "strength": 0.85,
        "applies_to": "all"
      },
      {
        "pattern": "Critical financial notifications prioritized",
        "strength": 0.9,
        "applies_to": "payment_failed,billing_*"
      }
    ]
  }
}
```

---

### Scenario 3: Add More Learning Data

**Context:** Multiple interactions teach the system user preferences

```bash
# Feedback 2: Order shipped notification
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.learn_from_feedback \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_id": "notif-002",
      "notification_type": "order_shipped",
      "user_response": {
        "action_taken": "opened",
        "time_to_action": 300,
        "importance_rating": 3,
        "channel_used": "email"
      }
    }
  }'

# Feedback 3: Marketing notification
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.learn_from_feedback \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_id": "notif-003",
      "notification_type": "marketing_promo",
      "user_response": {
        "action_taken": "dismissed",
        "time_to_action": 2,
        "importance_rating": 1,
        "channel_used": "push"
      }
    }
  }'
```

**After 3 feedbacks:** User now has 9 learned patterns (3 per feedback, top 10 kept)

---

### Scenario 4: Maturing User - Moderate 3-Specialist Analysis

**Context:** After 3+ feedbacks, system uses moderate analysis (cost optimization)

**Expected Graph:** 3 specialists (urgency, channel, timing) → streamlined synthesis

```bash
# Step 3: New notification with learned context (3 specialists)
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_type": "order_shipped",
      "notification_data": {
        "order_id": "ORD-789",
        "tracking": "1Z999AA1234567890",
        "estimated_delivery": "2025-01-26"
      },
      "context": {
        "user_timezone": "America/Los_Angeles",
        "current_time": "2025-01-24T18:00:00Z",
        "user_tier": "premium"
      }
    }
  }'
```

**What to observe in AgentField UI:**
- Only 3 specialists now (not 5!)
- Faster execution (40% fewer AI calls)
- Still high-quality decision
- `pattern_count: 9` → triggers moderate analysis
- System leverages learned patterns from memory

**Expected Output:**
```json
{
  "result": {
    "decision": {
      "deliver": "now",
      "channel": "email",
      "priority": 65,
      "reasoning": "Based on learned patterns, user prefers email for shipping updates..."
    },
    "pattern_count": 9,
    "analysis_depth": "moderate"
  }
}
```

---

### Scenario 5: Continue Learning to Reach Streamlined Mode

```bash
# Add 7 more feedbacks to reach 10+ patterns
for i in {4..10}; do
  curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.learn_from_feedback \
    -H "Content-Type: application/json" \
    -d "{
      \"input\": {
        \"user_id\": \"demo-user-001\",
        \"notification_id\": \"notif-00$i\",
        \"notification_type\": \"various_types\",
        \"user_response\": {
          \"action_taken\": \"opened\",
          \"time_to_action\": 60,
          \"importance_rating\": 3,
          \"channel_used\": \"email\"
        }
      }
    }"
done
```

---

### Scenario 6: Confident User - Streamlined 2-Specialist Analysis

**Context:** After 10+ feedbacks, system is confident and uses minimal analysis

**Expected Graph:** Only 2 specialists (urgency + channel) → quick synthesis

```bash
# Step 4: Streamlined analysis (maximum efficiency)
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_type": "account_update",
      "notification_data": {
        "update_type": "profile_changed",
        "fields": ["email", "phone"]
      },
      "context": {
        "user_timezone": "America/Los_Angeles",
        "current_time": "2025-01-25T09:00:00Z",
        "user_tier": "premium"
      }
    }
  }'
```

**What to observe in AgentField UI:**
- Only 2 specialists! (urgency + channel)
- 50% cost reduction vs full analysis
- Fast execution
- Still intelligent decision based on learned patterns
- `pattern_count: 10+` → triggers streamlined

**Expected Output:**
```json
{
  "result": {
    "decision": {
      "deliver": "now",
      "channel": "email",
      "priority": 50,
      "reasoning": "Routine update, user prefers email based on history..."
    },
    "pattern_count": 30,
    "analysis_depth": "streamlined"
  }
}
```

---

### Scenario 7: Multi-User Comparison

**Context:** Show different users getting different orchestration depths

```bash
# New user - gets full analysis
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "new-user-999",
      "notification_type": "payment_failed",
      "notification_data": {"amount": 99.99},
      "context": {
        "user_timezone": "America/New_York",
        "current_time": "2025-01-24T15:00:00Z",
        "user_tier": "free"
      }
    }
  }'

# Learned user - gets moderate analysis
curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "demo-user-001",
      "notification_type": "payment_failed",
      "notification_data": {"amount": 99.99},
      "context": {
        "user_timezone": "America/Los_Angeles",
        "current_time": "2025-01-24T15:00:00Z",
        "user_tier": "premium"
      }
    }
  }'
```

**Compare the workflow graphs side-by-side in AgentField UI!**

---

## Understanding the Workflow Graphs

### Graph Elements

1. **Specialist Nodes** (parallel branches)
   - Each specialist reasoner appears as a separate node
   - Emit notes showing their analysis
   - Run in parallel for speed
   - Tag: `[specialist, urgency/channel/etc]`

2. **Synthesis Node** (convergence point)
   - Where parallel branches merge
   - Combines all specialist perspectives
   - Tag: `[synthesis, decision]`

3. **Orchestrator Node** (entry point)
   - `route_notification` - decides depth
   - Tag: `[orchestration, full/moderate/streamlined]`

4. **Learning Nodes** (separate graph)
   - Appears when feedback is processed
   - 3 parallel insight extractors
   - Tag: `[learning, behavior/channel/preference]`

### Reading the Notes

Each node emits structured notes:

```
⚡ Urgency: 95/100 (immediate)           # Urgency specialist
📱 Channel: sms (confidence: 0.92)       # Channel specialist
👤 User: active, engagement 85%          # User state specialist
⏰ Timing: now - critical payment issue  # Timing specialist
🔍 Context: critical priority - ...      # Context specialist
🧩 Synthesizing 5 specialist perspectives... # Synthesis
✨ Final: now via sms (priority 95/100) # Final decision
```

---

## Cost Optimization Notes

### Current Configuration (Visual Demo Mode)

- **New users:** 6 AI calls (5 specialists + synthesis)
- **Learning users:** 4 AI calls (3 specialists + synthesis)
- **Confident users:** 3 AI calls (2 specialists + synthesis)
- **Learning:** 3 AI calls per feedback (3 parallel specialists)

**Average across user lifecycle:** ~4 AI calls per decision

### Production Optimization Options

To reduce costs while maintaining quality:

#### Option 1: Remove Context Specialist
```python
# In orchestrate_full_analysis, remove:
# context_task = router.app.call(...)
```
**Savings:** -17% AI calls (5→4 specialists)

#### Option 2: Remove User State Specialist
```python
# Remove user_state_task
```
**Savings:** -17% AI calls

#### Option 3: Start at Moderate (skip full)
```python
# In route_notification, change:
if pattern_count < 3:
    # Use moderate instead of full
```
**Savings:** -33% for new users

#### Option 4: Single-shot for confident users
```python
# Skip specialists entirely for 10+ patterns
# Use direct AI call with learned context
```
**Savings:** -67% for experienced users

**Recommended production config:** Remove context specialist, start at moderate
- **New users:** 4 AI calls
- **Learning users:** 4 AI calls
- **Confident:** 3 AI calls
- **Average:** ~3.5 AI calls per decision
- **Savings:** 30% cost reduction, minimal quality impact

---

## Memory Architecture

### Actor Scope (Per-User Learning)

Each user has private memory storing:

```python
{
  "learned_patterns": [
    {
      "pattern": "Responds urgently to payment issues",
      "strength": 0.9,
      "applies_to": "payment_failed"
    },
    # ... top 10 patterns by strength
  ],
  "channel_effectiveness": {
    "email": 0.65,  # 65% engagement rate
    "sms": 0.92,    # 92% engagement rate
    "push": 0.45,   # 45% engagement rate
    "app": 0.55     # 55% engagement rate
  },
  "sample_size": 30  # Number of feedback samples
}
```

**Key:** `router.memory.actor(user_id)`

### Workflow Scope (Execution Context)

Temporary state during decision workflow:

```python
{
  "notification_type": "payment_failed",
  "user_context": {...},
  "final_decision": {...}
}
```

**Key:** `router.memory.set()` (auto-scoped to workflow)

### Global Scope (System-Wide Patterns)

Cross-user insights (future enhancement):

```python
{
  "optimal_timing_patterns": {
    "peak_hours": [9, 10, 14, 15, 19],
    "avoid_hours": [0, 1, 2, 3, 4, 5, 6, 7]
  }
}
```

**Key:** `router.memory.global_scope`

---

## API Reference

### Main Endpoints

#### route_notification
**Purpose:** Make notification decision with adaptive orchestration

**Input:**
```json
{
  "user_id": "string",
  "notification_type": "string",
  "notification_data": {
    "amount": 99.99,
    "custom_field": "value"
  },
  "context": {
    "user_timezone": "America/Los_Angeles",
    "current_time": "ISO-8601",
    "user_tier": "premium"
  }
}
```

**Output:**
```json
{
  "decision": {
    "deliver": "now|delay|batch|skip",
    "channel": "email|sms|push|app",
    "priority": 85,
    "reasoning": "explanation"
  },
  "pattern_count": 5,
  "analysis_depth": "full|moderate|streamlined"
}
```

#### learn_from_feedback
**Purpose:** Extract insights from user interaction

**Input:**
```json
{
  "user_id": "string",
  "notification_id": "string",
  "notification_type": "string",
  "user_response": {
    "action_taken": "opened|dismissed|ignored",
    "time_to_action": 120,
    "importance_rating": 4,
    "channel_used": "sms"
  }
}
```

**Output:**
```json
{
  "patterns_learned": 3,
  "sample_size": 15,
  "insights": [
    {
      "pattern": "description",
      "strength": 0.85,
      "applies_to": "notification_types"
    }
  ]
}
```

---

## Production Integration Example

```python
import requests

AGENTFIELD_API = "http://localhost:8080/api/v1/execute"

class NotificationIntelligence:
    """Production wrapper for notification intelligence agent."""

    def decide(self, user_id, notification_type, data, context):
        """Get AI recommendation for notification handling."""
        response = requests.post(
            f"{AGENTFIELD_API}/notification-intelligence.route_notification",
            json={
                "input": {
                    "user_id": user_id,
                    "notification_type": notification_type,
                    "notification_data": data,
                    "context": context
                }
            },
            timeout=10
        )
        return response.json()["result"]["decision"]

    def learn(self, user_id, notification_id, notification_type, user_response):
        """Teach the system from user behavior."""
        response = requests.post(
            f"{AGENTFIELD_API}/notification-intelligence.learn_from_feedback",
            json={
                "input": {
                    "user_id": user_id,
                    "notification_id": notification_id,
                    "notification_type": notification_type,
                    "user_response": user_response
                }
            },
            timeout=10
        )
        return response.json()["result"]

# Usage
agent = NotificationIntelligence()

# Get decision
decision = agent.decide(
    user_id="user-123",
    notification_type="payment_failed",
    data={"amount": 99.99},
    context={
        "user_timezone": "America/Los_Angeles",
        "current_time": "2025-01-24T15:00:00Z",
        "user_tier": "premium"
    }
)

# Execute notification based on decision
if decision["deliver"] == "now":
    send_notification(
        channel=decision["channel"],
        priority=decision["priority"]
    )

# Later, when user interacts
learning = agent.learn(
    user_id="user-123",
    notification_id="notif-456",
    notification_type="payment_failed",
    user_response={
        "action_taken": "opened",
        "time_to_action": 30,
        "channel_used": "sms"
    }
)

print(f"System learned {learning['patterns_learned']} new patterns")
```

---

## Key Innovations

### 1. Visual Multi-Agent Orchestration
- Each specialist appears as a node in workflow graph
- Parallel execution creates impressive star patterns
- Synthesis nodes show convergence
- Educational and production-ready

### 2. Adaptive Intelligence
- New users: Deep analysis (learn quickly)
- Learning users: Balanced analysis (optimize)
- Confident users: Streamlined (minimize cost)
- Automatically evolves per user

### 3. Continuous Learning
- Every feedback creates learning workflow
- 3 parallel insight extractors
- Top-10 pattern retention
- Channel effectiveness tracking

### 4. Cost Optimization
- Starts expensive, gets cheaper
- 50-67% cost reduction for learned users
- Quality maintained through learned patterns
- Configurable depth vs cost tradeoff

---

## Use Cases

### E-commerce
- Payment failures → instant SMS
- Order updates → email digest
- Marketing → skip low-engagement users

### SaaS
- Critical alerts → immediate push
- Feature updates → batch weekly
- Usage warnings → adaptive timing

### Healthcare
- Test results → urgent SMS
- Appointment reminders → day-before email
- Wellness tips → skip non-engaged

### Fintech
- Fraud alerts → instant multi-channel
- Transaction updates → learned preference
- Account notices → optimized timing

---

## Development Tips

### Viewing Workflow Graphs

1. Open the control plane UI at `http://localhost:8080`
2. Navigate to "Workflows" tab
3. Each execution shows as a card
4. Click to see full graph visualization
5. Hover nodes to see notes and timing

### Using the Frontend UI

1. Open `http://localhost:3000` in your browser
2. Select a pre-built scenario or configure a custom one
3. Click "Run" to execute and watch the decision graph animate in real-time
4. View the agent's reasoning and final decision

### Docker Commands

```bash
# Start all services
docker compose up

# Start in background
docker compose up -d

# View logs
docker compose logs -f

# Rebuild after code changes
docker compose up --build

# Stop all services
docker compose down

# Reset data (clear AgentField state)
docker compose down -v
```

### Testing Learning Progression

```bash
# Quick script to simulate user lifecycle
for i in {1..15}; do
  # Make decision
  curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.route_notification \
    -H "Content-Type: application/json" \
    -d "{\"input\": {\"user_id\": \"test-user\", \"notification_type\": \"test_$i\", \"notification_data\": {}, \"context\": {\"user_timezone\": \"UTC\", \"current_time\": \"2025-01-24T12:00:00Z\", \"user_tier\": \"free\"}}}"

  # Provide feedback
  curl -X POST http://localhost:8080/api/v1/execute/notification-intelligence.learn_from_feedback \
    -H "Content-Type: application/json" \
    -d "{\"input\": {\"user_id\": \"test-user\", \"notification_id\": \"n$i\", \"notification_type\": \"test_$i\", \"user_response\": {\"action_taken\": \"opened\", \"time_to_action\": 60, \"channel_used\": \"email\"}}}"
done
```

Watch the workflow graphs evolve from 5-specialist → 3-specialist → 2-specialist!

---

## Architecture Philosophy

This example embodies **guided autonomy**:

- **Guided**: Specialists have focused domains, orchestrator controls depth
- **Autonomous**: AI self-determines optimal paths, learns patterns
- **Visual**: Every decision visible in workflow graph
- **Production**: Cost-optimized, scalable, enterprise-ready

**The future of backend systems: software that thinks strategically and improves continuously.**
