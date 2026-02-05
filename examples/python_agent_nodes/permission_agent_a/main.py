"""
Permission Agent A (Caller)

A normal agent that tries to call permission-agent-b (a protected agent).
Used to test the VC authorization system end-to-end.

Test flow:
  1. Start control plane with authorization enabled
  2. Start permission-agent-b (the protected target)
  3. Start permission-agent-a (this agent)
  4. Call: POST /api/v1/execute/permission-agent-a.call_payment_gateway
     -> This agent will try to call permission-agent-b.process_payment via the control plane
     -> Should be denied (403) until an admin approves the permission
"""

from agentfield import Agent
import os

app = Agent(
    node_id="permission-agent-a",
    agentfield_server=os.getenv("AGENTFIELD_URL", "http://localhost:8080"),
)


@app.skill()
def ping() -> dict:
    """Simple health check - no cross-agent call, should always work."""
    return {"status": "ok", "agent": "permission-agent-a"}


@app.reasoner()
async def call_payment_gateway(amount: float, currency: str = "USD") -> dict:
    """
    Calls permission-agent-b.process_payment through the control plane.
    This will trigger the permission check middleware since permission-agent-b
    is a protected agent (matched by agent_id pattern "payment-gateway"...
    but our agent is called "permission-agent-b", so we also call the
    actual payment-gateway agent to test the agent_id rule).
    """
    result = await app.call(
        "permission-agent-b.process_payment",
        amount=amount,
        currency=currency,
    )
    return {
        "source": "permission-agent-a",
        "delegation_result": result,
    }


if __name__ == "__main__":
    print("🔑 Permission Agent A (Caller)")
    print("📍 Node: permission-agent-a")
    app.run(auto_port=True)
