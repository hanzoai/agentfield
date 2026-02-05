"""
Permission Agent B (Protected Target)

A protected agent that requires permission to call.
Protected by the agent_id rule matching "permission-agent-b" in the config,
and also tagged "sensitive" to test tag-based protection.

Test flow:
  1. Start control plane with authorization enabled
  2. Start this agent
  3. Try calling it from permission-agent-a -> should be denied
  4. Approve permission via admin API -> should succeed
"""

from agentfield import Agent
import os

app = Agent(
    node_id="permission-agent-b",
    agentfield_server=os.getenv("AGENTFIELD_URL", "http://localhost:8080"),
    tags=["sensitive", "payments"],
)


@app.skill()
def process_payment(amount: float, currency: str = "USD") -> dict:
    """Process a payment. This is a protected operation."""
    return {
        "status": "processed",
        "amount": amount,
        "currency": currency,
        "agent": "permission-agent-b",
        "message": f"Payment of {amount} {currency} processed successfully",
    }


@app.skill()
def get_balance() -> dict:
    """Check balance. Also protected since the whole agent is protected."""
    return {
        "balance": 10000.00,
        "currency": "USD",
        "agent": "permission-agent-b",
    }


if __name__ == "__main__":
    print("🔒 Permission Agent B (Protected Target)")
    print("📍 Node: permission-agent-b")
    print("🏷️  Tags: sensitive, payments")
    app.run(auto_port=True)
