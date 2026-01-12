"""
Adaptive Multi-Agent Notification Intelligence

Visual multi-agent orchestration demonstrating:
- Parallel specialist reasoners creating impressive workflow graphs
- Adaptive routing based on learning maturity
- Continuous learning from user feedback
- Meta-level intelligence optimization

Production-ready backend AI for notification systems.
"""

import os
from agentfield import Agent, AIConfig
from reasoners import router


# Initialize agent
app = Agent(
    node_id="notification-intelligence",
    version="2.0.0",
    description="Adaptive multi-agent notification intelligence with visual orchestration",
    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
    ai_config=AIConfig(
        model=os.getenv("AI_MODEL", "openrouter/openai/gpt-oss-120b"),
    ),
)

# Include the enhanced router with all specialist reasoners
app.include_router(router)


if __name__ == "__main__":
    # Start the agent server
    port_env = os.getenv("PORT")
    if port_env is None:
        app.run(auto_port=True, host="0.0.0.0")
    else:
        app.run(port=int(port_env), host="0.0.0.0")
