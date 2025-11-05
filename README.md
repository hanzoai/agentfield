<div align="center">

# Haxen

### Kubernetes for AI Agents
### **with Identity, Scale, and Trust**

**Run AI agents like microservices. Distributed, observable, production-grade.**

**Cryptographic identity and tamper-proof audit trails built in.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev/)
[![Python](https://img.shields.io/badge/python-3.9+-3776AB.svg)](https://www.python.org/)
[![Discord](https://img.shields.io/badge/discord-join-5865F2.svg)](https://discord.gg/your-discord)
[![Docs](https://img.shields.io/badge/docs-haxen.ai-purple.svg)](https://haxen.ai)

[Quick Start](#-quick-start-5-minutes) • [Architecture](#%EF%B8%8F-architecture) • [Features](#-what-you-get-out-of-the-box) • [Community](#-community)

</div>

---

## What is Haxen?

Haxen is **infrastructure for autonomous software**. Think of what Kubernetes did for containers, but for AI agents. Plus built-in identity and trust.

> **Haxen isn't a framework you extend with infrastructure. It IS the infrastructure.**

### The Problem

Agent frameworks (LangChain, CrewAI, etc.) are great for **prototypes**. But when you need production systems:

- ❌ **Monolithic deployments** - one team's change forces everyone to redeploy
- ❌ **No native APIs** - your React app can't call agents without custom wrappers
- ❌ **Manual orchestration** - you build your own queues, state management, and coordination
- ❌ **No observability** - good luck debugging multi-agent workflows
- ❌ **DIY infrastructure** - you're building webhooks, SSE, async execution, health checks from scratch
- ❌ **No identity or audit** - logs aren't proofs, compliance teams need cryptographic verification

**Frameworks build agents. Haxen runs them at scale, with trust.**

### The Solution

```
Traditional Frameworks = Flask (single app)
Haxen = Kubernetes + Auth0 for AI (distributed infrastructure + identity)
```

Haxen provides a **control plane** that treats AI agents as **production microservices**:

✅ **Deploy independently** - teams ship agents without coordination
✅ **REST API by default** - every agent function is instantly an endpoint
✅ **Auto-orchestration** - agents call each other, workflows track automatically
✅ **Real-time streaming** - SSE/WebSocket updates for frontends
✅ **Async execution** - durable queues with webhooks (HMAC-signed)
✅ **Built-in observability** - workflow DAGs, execution traces, agent notes, Prometheus metrics
✅ **Cryptographic identity** - DIDs for agents, VCs for audit trails
✅ **Production infrastructure** - health checks, Docker/K8s ready, horizontal scaling

---

## ⚡ See It In Action (30 seconds)

### The Scenario
You're building a customer support system with AI. You need 3 agents that coordinate:
- **Sentiment analyzer** - understands customer mood
- **Knowledge base** - finds solutions
- **Escalation handler** - creates urgent tickets

### Without Haxen: 3 Months of Infrastructure

You build: message queues, API wrappers, state management (Redis), webhook system, observability stack, health checks, deployment configs...

**Then** you write agent logic.

### With Haxen: Write 3 Functions, Deploy

```python
from haxen_sdk import Agent

# Agent 1: Support orchestrator
support = Agent("support-agent")

@support.reasoner()
async def handle_ticket(ticket: dict) -> dict:
    # Call agent 2 (different service, different team)
    sentiment = await support.call("sentiment-agent.analyze",
                                    text=ticket["message"])

    # Call agent 3 (knowledge base)
    solutions = await support.call("kb-agent.search",
                                    query=ticket["issue"])

    # Conditional logic - escalate if urgent
    if sentiment["urgency"] == "high":
        await support.call("escalation-agent.create_case", ticket=ticket)

    return {"solutions": solutions, "sentiment": sentiment}
```

**Deploy:**
```bash
haxen dev           # Start control plane
haxen run           # Deploy your agent
```

**You get automatically:**
- ✅ REST API: `POST /execute/support-agent.handle_ticket`
- ✅ Async execution: `POST /execute/async/...` with webhooks (HMAC-signed)
- ✅ Real-time streaming (SSE): Your frontend gets live updates
- ✅ Workflow DAG: Visual graph showing which agent called which
- ✅ Shared memory: All 3 agents access the same state automatically
- ✅ Observability: Prometheus metrics, execution traces, agent notes
- ✅ Identity: Cryptographic proof of every decision (DIDs + VCs)
- ✅ Health checks, Docker/K8s ready, horizontal scaling

**From your React app:**
```javascript
// Call agents via REST API (no custom SDK needed)
const response = await fetch('http://haxen:8080/api/v1/execute/support-agent.handle_ticket', {
  method: 'POST',
  body: JSON.stringify({ input: { ticket: {...} } })
});

// Stream real-time updates
const eventSource = new EventSource(
  `http://haxen:8080/api/v1/workflows/runs/${runId}/events/stream`
);
eventSource.onmessage = (e) => {
  console.log('Agent update:', JSON.parse(e.data));
};
```

**🎨 UI SCREENSHOT #1 (HERO): Add here**
> **What to show:** Workflow DAG visualization from the Haxen UI showing the 3 agents (support-agent → sentiment-agent, support-agent → kb-agent, support-agent → escalation-agent) with execution times, status indicators (green checkmarks), and the visual graph. This is the "wow" moment that shows developers the automatic observability.
>
> **Recommended dimensions:** 1200x700px, annotate with arrows pointing to: "Auto-generated DAG", "Execution times", "Agent-to-agent calls"

**Scale individual agents:**
```bash
kubectl scale deployment sentiment-agent --replicas=10
# Other agents unaffected
```

### That's the difference.

Haxen **is** the infrastructure you'd otherwise spend 3 months building.

---

## 🚀 Quick Start (5 Minutes)

### Install Haxen

```bash
# macOS/Linux
curl -fsSL https://haxen.ai/install.sh | bash

# Or with Go
go install github.com/agentfield/haxen/cmd/haxen@latest
```

### Create Your First Multi-Agent System

```bash
haxen init my-agents
cd my-agents
```

**Write your agents** (see example above) **→ Run locally** (`haxen dev` + `haxen run`) **→ Test via REST API or React app**

[Full quick start guide →](https://haxen.ai/docs/quick-start)

---

## 🏗️ Architecture

### Deploy AI Agents Like Kubernetes Deploys Containers

Haxen uses a **two-layer design**: a stateless **control plane** (like K8s control plane) and independent **agent nodes** (like pods):

```
┌───────────────────────────────────────────────────────────────┐
│                   HAXEN CONTROL PLANE                          │
│           (Stateless Go Services - Scale Horizontally)         │
├───────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐ ┌──────────────────┐ ┌────────────────┐ │
│  │ SCALE           │ │ TRUST &          │ │ PRODUCTION     │ │
│  │ INFRASTRUCTURE  │ │ GOVERNANCE       │ │ HARDENING      │ │
│  ├─────────────────┤ ├──────────────────┤ ├────────────────┤ │
│  │ • Workflow      │ │ • Auto DIDs      │ │ • Workflow     │ │
│  │   Engine (DAGs) │ │ • Verifiable     │ │   DAGs (UI)    │ │
│  │ • Execution     │ │   Credentials    │ │ • Prometheus   │ │
│  │   Queue         │ │ • Audit Trails   │ │   Metrics      │ │
│  │ • Async +       │ │ • Crypto Proofs  │ │ • Health       │ │
│  │   Webhooks      │ │ • Policy Engine  │ │   Checks       │ │
│  │ • Agent         │ │ • Non-           │ │ • Auto         │ │
│  │   Discovery     │ │   Repudiation    │ │   Retries      │ │
│  │ • Event         │ │                  │ │ • Zero-Config  │ │
│  │   Streaming     │ │                  │ │   Memory       │ │
│  └─────────────────┘ └──────────────────┘ └────────────────┘ │
│                                                                │
│  Deploy independently → Coordinate automatically → Trust built-in │
└───────────────────────────────────────────────────────────────┘
       ▲                        ▲                      ▲
       │    REST API / gRPC / WebSocket / HTTP        │
       │    (Language-agnostic communication)         │
       ▼                        ▼                      ▼
┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐
│  Agent Node   │  │ Agent Node   │  │   Agent Node        │
│  (Container)  │  │ (Container)  │  │   (Container)       │
│               │  │              │  │                     │
│  Python SDK   │  │  Go SDK      │  │   Any Language      │
│  support-     │  │  analytics-  │  │   payment-          │
│  agent:v2     │  │  agent:v1    │  │   agent:v3          │
│               │  │              │  │   (REST/gRPC)       │
│  Team: CS     │  │  Team: Data  │  │   Team: Finance     │
│  Replicas: 5  │  │  Replicas: 2 │  │   Replicas: 3       │
└───────────────┘  └──────────────┘  └─────────────────────┘
```

### Think Kubernetes, But for AI

| Kubernetes             | Haxen                 | What It Means                                  |
| ---------------------- | --------------------- | ---------------------------------------------- |
| **Pods**               | **Agent Nodes**       | Your AI agent runs in a container              |
| **Services**           | **Agent Registry**    | Control plane discovers agents automatically   |
| **kubectl apply**      | **haxen run**         | Deploy your agent independently                |
| **Horizontal scaling** | **Scale agent nodes** | Add more replicas per agent                    |
| **Service mesh**       | **Control plane**     | Automatic routing, observability, state        |
| **Ingress**            | **API Gateway**       | Every agent function is a REST endpoint        |
| **Language-agnostic**  | **REST/gRPC API**     | Use Python, Go, Rust, JavaScript, any language |

### How It Works

1. **Write agents in any language** - Python SDK, Go SDK, or raw REST/gRPC
2. **Deploy as containers** - `docker build` + `haxen run` or `kubectl apply`
3. **Control plane orchestrates** - routing, state, workflows, identity, observability
4. **Agents scale independently** - each team owns their nodes, deploys on their schedule
5. **Everything auto-coordinates** - agents call each other via control plane, memory syncs, workflows track

**Key Insight:** Each agent is a **microservice**. Teams deploy independently. The control plane makes them coordinate like a single system.

**Language Flexibility:** Use our Python/Go SDKs for convenience, or implement the REST/gRPC protocol directly in any language. The control plane is language-agnostic by design.

[See detailed architecture →](https://haxen.ai/docs/architecture)

---

## ✨ What You Get Out of the Box

### 🎯 Microservices Patterns for AI

| Feature                    | What It Does                                                          |
| -------------------------- | --------------------------------------------------------------------- |
| **Service Discovery**      | Agents register on startup. Control plane routes calls automatically. |
| **API Gateway**            | Every agent function = REST endpoint (OpenAPI spec generated)         |
| **Independent Deployment** | Teams deploy agents separately. Zero coordination.                    |
| **Horizontal Scaling**     | Scale individual agents. Control plane load balances.                 |
| **Health Checks**          | Built-in `/health/live` and `/health/ready` for K8s                   |
| **Language-Agnostic**      | Python SDK, Go SDK, or raw REST/gRPC                                  |

### ⚡ Top 3 Features Developers Love

<details>
<summary><strong>1. Real-Time Streaming (SSE) - Keep Frontends Updated</strong></summary>

```javascript
// React: Live updates as multi-agent workflow executes
const eventSource = new EventSource(`/api/v1/workflows/runs/${runId}/events/stream`);
eventSource.addEventListener('workflow_run_event', (e) => {
  const event = JSON.parse(e.data);

  if (event.event_type === 'execution_started') {
    setStatus(`Processing: ${event.payload.target}`);
  } else if (event.event_type === 'workflow_completed') {
    setStatus('Complete!');
  }
});
```

**What you get:**
- Real-time workflow updates (execution started, completed, failed)
- Agent notes streaming (AI reasoning visible in real-time)
- Memory change events (see when agents update shared state)
- System-wide execution monitoring

**🎨 UI SCREENSHOT #2: Add here**
> **What to show:** Haxen UI showing a live streaming view of a workflow execution. Display the real-time event stream with timestamps, event types, and a progress indicator. Show the UI updating as events come in.
>
> **Caption:** "Real-time SSE streaming - your frontend stays in sync with multi-agent workflows"

</details>

<details>
<summary><strong>2. Async Execution + Webhooks - Don't Block on AI</strong></summary>

**The Problem:** Your AI task takes 10 minutes. You can't block the HTTP request.

**The Solution:**

```bash
# Queue task, return immediately (202 Accepted)
curl -X POST http://haxen:8080/api/v1/execute/async/research-agent.deep_analysis \
  -d '{
    "input": {"topic": "autonomous software market"},
    "webhook": {
      "url": "https://your-app.com/haxen/callback",
      "secret": "your-webhook-secret"
    }
  }'

# Response (instant):
{
  "execution_id": "exec_abc123",
  "status": "queued",
  "webhook_registered": true
}
```

**10 minutes later**, Haxen POSTs the result to your webhook with **HMAC-SHA256 signature**:

```json
{
  "event": "execution.completed",
  "execution_id": "exec_abc123",
  "result": {
    "market_size": "$2.3B",
    "growth_rate": "47% YoY",
    "report_url": "https://storage.example.com/report.pdf"
  },
  "duration_ms": 605000
}
```

**What's handled automatically:**
- Durable queues (PostgreSQL `FOR UPDATE SKIP LOCKED`)
- Exponential backoff retries
- Webhook delivery with up to 6 retry attempts
- Fair scheduling (prevents queue monopolization)
- Backpressure controls

[See webhook verification examples →](https://haxen.ai/docs/webhooks)

</details>

<details>
<summary><strong>3. Identity & Cryptographic Audit - Pass Compliance</strong></summary>

**The Problem:** Your AI agent approved a $500K loan. Two months later, regulators ask:

> "Prove this specific agent made this decision with these exact inputs. Prove it wasn't tampered with."

**Logs can be edited. Screenshots can be faked. You need cryptographic proof.**

**Haxen's Solution:**

Every agent gets a **DID (Decentralized Identifier)**. Every execution can generate a **Verifiable Credential (VC)** - a cryptographically signed proof.

```python
# Enable per agent (opt-in)
if app.vc_generator:
    app.vc_generator.set_enabled(True)

@app.reasoner()
async def approve_loan(application: dict) -> Decision:
    decision = await app.ai("Evaluate loan risk", ...)
    # VC generated automatically with DID signature + input/output hashes
    return decision
```

**For auditors/compliance:**

```bash
# Export cryptographic proof chain
curl http://haxen:8080/api/v1/did/workflow/wf_abc123/vc-chain > audit.json

# Verify offline (no access to your systems needed)
haxen verify audit.json
# ✓ All signatures valid
# ✓ No tampering detected
# ✓ Complete provenance chain
```

**What this means:**

✅ **Pass compliance audits** - export tamper-proof VC chains for regulators
✅ **Debug with certainty** - know exactly which agent version made which decision
✅ **Non-repudiation** - agents can't deny their actions (cryptographically impossible)
✅ **Enterprise sales** - "built-in audit trails" closes deals with regulated industries

**🎨 UI SCREENSHOT #3: Add here**
> **What to show:** Haxen UI showing the DID/VC verification interface. Display a workflow with DIDs for each agent, the VC chain visualization, and the verification status (green checkmarks showing "All signatures valid").
>
> **Caption:** "Cryptographic identity and verifiable credentials - tamper-proof audit trails built in"

</details>

### 📦 Complete Production Infrastructure

<details>
<summary>Click to see full infrastructure features</summary>

- ✅ **Workflow DAGs** - Visual execution graphs, auto-generated
- ✅ **Prometheus metrics** - Request rates, latencies, error rates (automatic, no instrumentation)
- ✅ **Durable queues** - Lease-based processing, survives crashes
- ✅ **Zero-config shared memory** - Global → Actor → Session → Workflow scopes (automatic)
- ✅ **Agent notes** - Structured logging from distributed agents
- ✅ **Graceful shutdown** - Completes in-flight work before exit
- ✅ **Health checks** - `/health/live` and `/health/ready` endpoints
- ✅ **Docker/K8s ready** - Deploy like any containerized service
- ✅ **Horizontal scaling** - Stateless control plane + independent agent nodes
- ✅ **Multi-language support** - REST API works with React, Go, .NET, mobile apps

</details>

**🎨 UI SCREENSHOT #4: Add here**
> **What to show:** Haxen UI dashboard showing the complete observability stack - Prometheus metrics graphs (request rate, latency), workflow DAG list, agent status (healthy/unhealthy), and real-time execution monitoring.
>
> **Caption:** "Production-grade observability out of the box - metrics, DAGs, health checks, and real-time monitoring"

[Detailed features docs →](https://haxen.ai/docs/features)

---

## 🐳 Deployment

**Local dev:** `haxen dev` + `haxen run`

**Docker:** Compose files included

**Kubernetes:** Helm charts + manifests included

**Cloud:** Works on Railway, Render, Fly.io, AWS, GCP, Azure

Each agent deploys independently. Control plane coordinates automatically.

<details>
<summary>See deployment examples</summary>

**Docker Compose:**
```yaml
services:
  haxen-server:
    image: haxen/server:latest
    ports: ["8080:8080"]

  my-agent:
    build: ./agents/my-agent
    environment:
      - HAXEN_SERVER=http://haxen-server:8080
```

**Kubernetes:**
```bash
kubectl apply -f haxen-control-plane.yaml
kubectl apply -f my-agent-deployment.yaml
kubectl scale deployment my-agent --replicas=10
```

</details>

[Full deployment guides →](https://haxen.ai/docs/deployment)

---

## 🎯 When Do You Need Haxen?

### You're Hitting These Pain Points:

- ❌ Your monolithic agent app can't scale - one agent needs 10x capacity but you have to scale everything
- ❌ Your React/mobile app needs custom wrappers to call each agent
- ❌ You're manually coordinating between agents with message queues
- ❌ Debugging multi-agent flows means grep'ing logs from 5 different services
- ❌ You built webhooks, retries, and queue management... again
- ❌ Compliance is asking "prove this AI made this decision" and you have logs that could be edited

### Haxen Solves This

| You Need                                | Traditional Frameworks  | Haxen                                        |
| --------------------------------------- | ----------------------- | -------------------------------------------- |
| **Chatbot prototype**                   | ✅ Quick start           | ✅ Quick start + production infrastructure    |
| **Learning agent concepts**             | ✅ Simple                | ✅ Simple + real-world patterns               |
| **Single app, one team**                | ✅ Lightweight           | ✅ Lightweight setup, enterprise-ready output |
|                                         |                         |                                              |
| **Production multi-agent system**       | ❌ DIY infrastructure    | ✅ Built-in                                   |
| **Multiple teams, independent deploys** | ❌ Coordination hell     | ✅ Deploy independently                       |
| **Scale agents like microservices**     | ❌ Manual                | ✅ Kubernetes-style                           |
| **Compliance/audit trails**             | ❌ Build yourself        | ✅ Cryptographic proofs                       |
| **Frontend integration (React/mobile)** | ❌ Custom wrappers       | ✅ REST API                                   |
| **Long-running tasks (5+ min)**         | ❌ DIY queues + webhooks | ✅ Built-in async + webhooks                  |

**Same code. Same patterns. Zero migration.**

Traditional frameworks force you to rebuild when you scale. Haxen grows with you.

### The Bottom Line

**Frameworks = Build agents** (perfect for learning)

**Haxen = Run agents at any scale** (perfect from prototype to production)

Start with Haxen. Skip the migration pain.

---

## 🌍 Community

We're building Haxen in the open. Join us:

- **[Discord](https://discord.gg/your-discord)** - Get help, share projects, discuss architecture
- **[GitHub Discussions](https://github.com/agentfield/haxen/discussions)** - Feature requests, Q&A
- **[Documentation](https://haxen.ai/docs)** - Guides, API reference, examples
- **[Twitter/X](https://x.com/haxen_dev)** - Updates and announcements

### Contributing

Apache 2.0 licensed. Built by developers like you.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

---

## 📖 Resources

- **[Documentation](https://haxen.ai/docs)** - Complete guides and API reference
- **[Quick Start Tutorial](https://haxen.ai/docs/quick-start)** - Build your first agent in 5 minutes
- **[Architecture Deep Dive](https://haxen.ai/docs/architecture)** - How Haxen works under the hood
- **[Examples Repository](https://github.com/agentfield/haxen-examples)** - Production-ready agent templates
- **[Blog](https://haxen.ai/blog)** - Tutorials, case studies, best practices

---

<div align="center">

### ⭐ Star us to follow development

**Built by developers who got tired of duct-taping agents together**

**Join the future of autonomous software**

[Website](https://haxen.ai) • [Docs](https://haxen.ai/docs) • [Discord](https://discord.gg/your-discord) • [Twitter](https://x.com/haxen_dev)

**License:** [Apache 2.0](LICENSE)

---

*We believe autonomous software needs infrastructure that respects what makes it different - agents that reason, decide, and coordinate - while providing the same operational excellence that made traditional software successful.*

</div>
