<div align="center">

<img src="assets/github hero.png" alt="AgentField - Kubernetes, for AI Agents" width="100%" />

# Kubernetes for AI Agents

### **Deploy, Scale, Observe, and Prove.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev/)
[![Python](https://img.shields.io/badge/python-3.9+-3776AB.svg)](https://www.python.org/)
[![Deploy with Docker](https://img.shields.io/badge/deploy-docker-2496ED.svg)](https://docs.docker.com/)

**[📚 Documentation](https://agentfield.ai/docs)** • **[⚡ Quick Start](#-quick-start-in-60-seconds)** • **[🧠 Why AgentField](#-why-agentfield)**

</div>

---

> **👋 Welcome Early Adopter!**
>
> You've discovered AgentField before our official launch. We're currently in private beta, gathering feedback from early users to shape the future of the autonomous software. Feel free to explore and test, and we'd love to hear your thoughts! Share feedback via [GitHub Issues](https://github.com/Agent-Field/agentfield/issues) or email us at contact@agentfield.ai. Please note that features and APIs are still being refined before our public release.

---

## 🚀 What is AgentField?

**AgentField is "Kubernetes for AI Agents."**

It is an open-source **Control Plane** that treats AI agents as first-class citizens. Instead of building fragile, monolithic scripts, AgentField lets you deploy agents as **independent microservices** that can discover each other, coordinate complex workflows, and scale infinitely—all with built-in observability and cryptographic trust.


Write standard Python (or Go). Get a production-grade distributed system automatically.

```python
from agentfield import Agent

# 1. Define an Agent (It's just a microservice)
app = Agent(node_id="researcher", model="gpt-4o")

# 2. Create a Skill (Deterministic code)
@app.skill()
def fetch_url(url: str) -> str:
    return requests.get(url).text

# 3. Create a Reasoner (AI-powered logic)
# This automatically becomes a REST API endpoint: POST /execute/researcher.summarize
@app.reasoner()
async def summarize(url: str) -> dict:
    content = fetch_url(url)
    # Native AI call with structured output
    return await app.ai(f"Summarize this content: {content}")

# 4. Run it
if __name__ == "__main__":
    app.run()
```

**What you get for free:**
*   ✅ **Instant API:** `POST /api/v1/execute/researcher.summarize`
*   ✅ **Durable Execution:** Resumes automatically if the server crashes.
*   ✅ **Observability:**  You get a full execution DAG, metrics, and logs automatically.
*   ✅ **Audit:** Every step produces a cryptographically signed Verifiable Credential.

---

## 🚀 Quick Start in 60 Seconds

### 1. Install
```bash
curl -fsSL https://agentfield.ai/install.sh | bash
```

### 2. Initialize
```bash
af init my-agent --defaults && cd my-agent
```

### 3. Run
```bash
af run
```

### 4. Call
```bash
curl -X POST http://localhost:8080/api/v1/execute/researcher.summarize \
  -H "Content-Type: application/json" \
  -d '{"input": {"url": "https://example.com"}}'
```

<details>
<summary>🐳 <strong>Docker / Troubleshooting</strong></summary>

If you are running AgentField in Docker, you may need to set a callback URL so the Control Plane can reach your agent:

```bash
export AGENT_CALLBACK_URL="http://host.docker.internal:8001"
```
</details>

---

## 🎨 See It In Action

<div align="center">
<img src="assets/UI.png" alt="AgentField Dashboard" width="100%" />
<br/>
<i>Real-time Observability • Execution DAGs • Verifiable Credentials</i>
</div>

---

## 🧠 Why AgentField?

**Software is starting to behave less like scripts and more like reasoning systems.**
Once agents act across APIs, data layers, and critical paths, they need infrastructure: identity, routing, retries, observability, policies. We built AgentField because agents should behave as predictably as microservices.

### From Prototype to Production

Most frameworks (LangChain, CrewAI) are great for prototyping. But when you move to production, you hit walls: **Non-deterministic execution times**, **Multi-agent coordination**, and **Compliance**.

AgentField isn't a framework you extend. It's **infrastructure** that solves these problems out of the box.

| Capability       | Traditional Frameworks           | AgentField (Infrastructure)                   |
| :--------------- | :------------------------------- | :-------------------------------------------- |
| **Architecture** | Monolithic application           | **Distributed Microservices**                 |
| **Team Model**   | Single team, single repo         | **Independent teams & deployments**           |
| **Integration**  | Custom SDK per language          | **Standard REST/gRPC APIs**                   |
| **Coordination** | Manual message passing           | **Service Discovery & Auto-DAGs**             |
| **Memory**       | Configure vector stores manually | **Zero-config Scoped Memory & Vector Search** |
| **Async**        | Roll your own queues             | **Durable Queues, Webhooks, Retries**         |
| **Trust**        | "Trust me" logs                  | **DIDs & Verifiable Credentials**             |

---

## 🎯 Who is this for?

*   **Backend Engineers** shipping AI into production who want standard APIs, not magic.
*   **Platform Teams** who don't want to build another homegrown orchestrator.
*   **Enterprise Teams** in regulated industries (Finance, Health) needing audit trails.
*   **Frontend Developers** who just want to `fetch()` an agent without Python headaches.

---

## 💎 Key Features

### 🧩 Scale Infrastructure
*   **Control Plane:** Stateless Go service that handles routing and state.
*   **Async by Default:** Fire-and-forget or wait for results. Handles long-running tasks (hours/days) with **Webhooks**.
*   **Shared Memory Fabric:** Built-in, scoped memory (Workflow/Session/User) with **Vector Search** out of the box. No Redis/Pinecone required.

### 🛡️ Identity & Trust
*   **W3C DIDs:** Every agent has a cryptographic identity.
*   **Verifiable Credentials:** Prove *exactly* what the AI did.
*   **Policy:** "Only agents signed by 'Finance' can access this tool."

### 🔭 Observability
*   **DAG Visualization:** See the logic flow in real-time.
*   **Metrics:** Prometheus endpoints at `/metrics`.
*   **Logs:** Structured, correlated logs.

---

## 🔌 Interoperability

Call your agents from anywhere. No SDK required.

**Frontend (React/Next.js):**
```javascript
const response = await fetch("http://localhost:8080/api/v1/execute/researcher.summarize", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ input: { url: "https://example.com" } }),
});
const result = await response.json();
```

---

## 🏗️ Architecture

<div align="center">
<img src="assets/arch.png" alt="AgentField Architecture Diagram" width="80%" />
</div>

---

## ⚖️ Is AgentField for you?

### ✅ YES if:
*   You are building **multi-agent systems**.
*   You need **independent deployment** (multiple teams).
*   You need **compliance/audit trails**.
*   You want **production infrastructure** (Queues, Retries, APIs).

### ❌ NO if:
*   You are building a **single-agent chatbot**.
*   You are just **prototyping** and don't care about scale yet.

---

## 🤝 Community

**Agents are becoming part of production backends. They need identity, governance, and infrastructure. That’s why AgentField exists.**

*   **[📚 Documentation](https://agentfield.ai/docs)**
*   **[💡 GitHub Discussions](https://github.com/agentfield/agentfield/discussions)**
*   **[🐦 Twitter/X](https://x.com/agentfield_dev)**
*   **[📦 Examples](https://github.com/agentfield/agentfield-examples)**

<div align="center">
**Built by developers who got tired of duct-taping agents together.**
**[🌐 Website](https://agentfield.ai)**

</div>
