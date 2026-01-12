"""
Demo API for Notification Intelligence UI.

Provides REST endpoints for triggering scenarios, submitting feedback,
and WebSocket for real-time agent event streaming.
"""

import os
import uuid
import httpx
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scenarios import (
    get_scenario,
    get_all_scenarios,
    get_demo_user,
    get_all_demo_users,
    Scenario,
)
from state import demo_state, ExecutionStatus, AgentEvent
from websocket import (
    websocket_endpoint,
    init_sse_bridge,
    sse_bridge,
    manager,
)


# Configuration
NOTIFICATION_AGENT_URL = os.getenv("NOTIFICATION_AGENT", "http://localhost:8001")
AGENTFIELD_SERVER_URL = os.getenv("AGENTFIELD_SERVER", "http://localhost:8080")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    import sys
    print(f"[Lifespan] Starting up, AGENTFIELD_SERVER_URL={AGENTFIELD_SERVER_URL}", flush=True)
    # Initialize SSE bridge
    bridge = init_sse_bridge(AGENTFIELD_SERVER_URL)
    print(f"[Lifespan] Bridge initialized, starting...", flush=True)
    await bridge.start()
    print(f"[Lifespan] Bridge started", flush=True)
    yield
    # Cleanup
    print(f"[Lifespan] Shutting down...", flush=True)
    await bridge.stop()


app = FastAPI(
    title="Notification Intelligence Demo API",
    description="Interactive demo for multi-agent notification orchestration",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class TriggerRequest(BaseModel):
    scenario_id: str
    user_id: str
    overrides: Optional[dict] = None


class CustomTriggerRequest(BaseModel):
    """Request for custom user-defined scenarios."""
    notification_type: str  # abandoned_cart, flash_sale, back_in_stock, price_drop, shipping_update
    notification_data: dict  # Type-specific data
    context: Optional[dict] = None  # Optional context overrides
    user_id: str = "user_new_001"  # Default demo user


class TriggerResponse(BaseModel):
    execution_id: str
    scenario_id: str
    user_id: str
    status: str


class FeedbackRequest(BaseModel):
    user_id: str
    notification_id: str
    response: str  # opened, ignored, dismissed


class UserStatsResponse(BaseModel):
    user_id: str
    pattern_count: int
    analysis_mode: str
    specialists_used: int
    notifications_sent: int
    open_rate: float
    channel_effectiveness: dict


# REST Endpoints

@app.get("/")
async def root():
    """Health check."""
    return {"status": "ok", "service": "notification-intelligence-demo"}


@app.get("/scenarios")
async def list_scenarios():
    """List all available demo scenarios."""
    scenarios = get_all_scenarios()
    return {
        "scenarios": [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "notification_type": s.notification_type.value,
            }
            for s in scenarios
        ]
    }


@app.get("/scenarios/{scenario_id}")
async def get_scenario_detail(scenario_id: str):
    """Get full details of a scenario."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return {
        "id": scenario.id,
        "name": scenario.name,
        "description": scenario.description,
        "notification_type": scenario.notification_type.value,
        "notification_data": scenario.notification_data,
        "context": scenario.context,
    }


@app.get("/users")
async def list_users():
    """List all demo users with their learning states."""
    users = get_all_demo_users()
    states = demo_state.get_all_user_states()
    state_map = {s.user_id: s for s in states}

    return {
        "users": [
            {
                "id": u["id"],
                "name": u["name"],
                "description": u["description"],
                "pattern_count": state_map.get(u["id"], u).pattern_count
                if hasattr(state_map.get(u["id"]), "pattern_count")
                else u.get("pattern_count", 0),
                "analysis_mode": state_map.get(u["id"]).analysis_mode
                if u["id"] in state_map
                else u.get("analysis_mode", "full"),
                "specialists_used": state_map.get(u["id"]).specialists_used
                if u["id"] in state_map
                else u.get("specialists_used", 5),
            }
            for u in users
        ]
    }


@app.get("/users/{user_id}/stats")
async def get_user_stats(user_id: str) -> UserStatsResponse:
    """Get detailed stats for a user."""
    state = demo_state.get_user_state(user_id)
    if not state:
        raise HTTPException(status_code=404, detail="User not found")

    return UserStatsResponse(
        user_id=state.user_id,
        pattern_count=state.pattern_count,
        analysis_mode=state.analysis_mode,
        specialists_used=state.specialists_used,
        notifications_sent=state.notifications_sent,
        open_rate=state.open_rate,
        channel_effectiveness=state.channel_effectiveness,
    )


@app.post("/trigger", response_model=TriggerResponse)
async def trigger_notification(request: TriggerRequest):
    """
    Trigger a notification scenario.

    This calls the notification-intelligence agent with the scenario
    data and streams the execution events via WebSocket.
    """
    scenario = get_scenario(request.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    user = demo_state.get_user_state(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate execution ID
    execution_id = f"exec_{uuid.uuid4().hex[:12]}"

    # Create execution in state
    execution = await demo_state.create_execution(
        execution_id=execution_id,
        user_id=request.user_id,
        scenario_id=request.scenario_id,
    )

    # Set SSE bridge to filter to this execution
    if sse_bridge:
        sse_bridge.set_execution_id(execution_id)

    # Broadcast execution started
    await manager.broadcast({
        "type": "execution_started",
        "execution_id": execution_id,
        "scenario": {
            "id": scenario.id,
            "name": scenario.name,
            "notification_type": scenario.notification_type.value,
        },
        "user": {
            "id": user.user_id,
            "analysis_mode": user.analysis_mode,
            "specialists_used": user.specialists_used,
        },
        "timestamp": datetime.now().isoformat(),
    })

    # Call notification-intelligence agent asynchronously
    # Don't await - let it run and stream events
    import asyncio
    asyncio.create_task(
        _execute_notification(execution_id, scenario, request.user_id, request.overrides)
    )

    return TriggerResponse(
        execution_id=execution_id,
        scenario_id=request.scenario_id,
        user_id=request.user_id,
        status="started",
    )


@app.post("/trigger-custom", response_model=TriggerResponse)
async def trigger_custom_notification(request: CustomTriggerRequest):
    """
    Trigger a custom user-defined notification scenario.

    Allows users to specify their own notification data and context
    instead of using predefined scenarios.
    """
    # Validate notification type
    valid_types = ["abandoned_cart", "flash_sale", "back_in_stock", "price_drop", "shipping_update"]
    if request.notification_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid notification_type. Must be one of: {valid_types}"
        )

    user = demo_state.get_user_state(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate execution ID
    execution_id = f"exec_{uuid.uuid4().hex[:12]}"

    # Create execution in state
    await demo_state.create_execution(
        execution_id=execution_id,
        user_id=request.user_id,
        scenario_id=f"custom_{request.notification_type}",
    )

    # Set SSE bridge to filter to this execution
    if sse_bridge:
        sse_bridge.set_execution_id(execution_id)

    # Broadcast execution started
    await manager.broadcast({
        "type": "execution_started",
        "execution_id": execution_id,
        "scenario": {
            "id": f"custom_{request.notification_type}",
            "name": f"Custom {request.notification_type.replace('_', ' ').title()}",
            "notification_type": request.notification_type,
        },
        "user": {
            "id": user.user_id,
            "analysis_mode": user.analysis_mode,
            "specialists_used": user.specialists_used,
        },
        "timestamp": datetime.now().isoformat(),
    })

    # Execute the custom notification asynchronously
    import asyncio
    asyncio.create_task(
        _execute_custom_notification(
            execution_id,
            request.notification_type,
            request.notification_data,
            request.context or {},
            request.user_id,
        )
    )

    return TriggerResponse(
        execution_id=execution_id,
        scenario_id=f"custom_{request.notification_type}",
        user_id=request.user_id,
        status="started",
    )


async def _execute_custom_notification(
    execution_id: str,
    notification_type: str,
    notification_data: dict,
    custom_context: dict,
    user_id: str,
):
    """Execute a custom notification scenario."""
    try:
        await demo_state.update_execution_status(execution_id, ExecutionStatus.RUNNING)

        # Get user state for demo overrides
        user_state = demo_state.get_user_state(user_id)

        # Build context with defaults and user overrides
        # Use the custom context's current_hour_user_timezone if provided for demo consistency
        custom_hour = custom_context.get("current_hour_user_timezone")
        if custom_hour is not None:
            demo_time = datetime.now().replace(hour=custom_hour, minute=0, second=0, microsecond=0)
        else:
            demo_time = datetime.now()

        context = {
            "current_time": demo_time.isoformat(),
            "user_timezone": "America/New_York",
            "user_tier": custom_context.get("user_tier", "standard"),
            "demo_analysis_depth": user_state.analysis_mode if user_state else "full",
            "demo_pattern_count": user_state.pattern_count if user_state else 0,
            **custom_context,
        }

        payload = {
            "user_id": user_id,
            "notification_type": notification_type,
            "notification_data": notification_data,
            "context": context,
        }

        # Call the notification-intelligence agent
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{NOTIFICATION_AGENT_URL}/reasoners/route_notification",
                json=payload,
            )

            if response.status_code == 200:
                result = response.json()
                await demo_state.set_result(execution_id, result)
                await demo_state.update_execution_status(
                    execution_id, ExecutionStatus.COMPLETED
                )

                await manager.broadcast({
                    "type": "execution_completed",
                    "execution_id": execution_id,
                    "result": result,
                    "timestamp": datetime.now().isoformat(),
                })
            elif response.status_code == 202:
                result = response.json()
                await manager.broadcast({
                    "type": "execution_processing",
                    "execution_id": execution_id,
                    "agent_execution_id": result.get("execution_id"),
                    "timestamp": datetime.now().isoformat(),
                })
            else:
                error = f"Agent returned {response.status_code}: {response.text}"
                await demo_state.set_error(execution_id, error)
                await demo_state.update_execution_status(
                    execution_id, ExecutionStatus.FAILED
                )

                await manager.broadcast({
                    "type": "execution_failed",
                    "execution_id": execution_id,
                    "error": error,
                    "timestamp": datetime.now().isoformat(),
                })

    except Exception as e:
        error = str(e)
        await demo_state.set_error(execution_id, error)
        await demo_state.update_execution_status(execution_id, ExecutionStatus.FAILED)

        await manager.broadcast({
            "type": "execution_failed",
            "execution_id": execution_id,
            "error": error,
            "timestamp": datetime.now().isoformat(),
        })


async def _execute_notification(
    execution_id: str,
    scenario: Scenario,
    user_id: str,
    overrides: Optional[dict],
):
    """Execute the notification intelligence agent."""
    try:
        await demo_state.update_execution_status(execution_id, ExecutionStatus.RUNNING)

        # Get user state for demo overrides
        user_state = demo_state.get_user_state(user_id)

        # Build request payload with required runtime context
        # Use the scenario's current_hour_user_timezone to derive current_time for demo consistency
        scenario_hour = scenario.context.get("current_hour_user_timezone", datetime.now().hour)
        demo_time = datetime.now().replace(hour=scenario_hour, minute=0, second=0, microsecond=0)

        context = {
            **scenario.context,
            "current_time": demo_time.isoformat(),
            "user_timezone": "America/New_York",
            "user_tier": scenario.context.get("loyalty_tier", "standard") or "standard",
            # Demo-only override so the agent can render different orchestration depths
            # without requiring pre-seeded long-term memory.
            "demo_analysis_depth": user_state.analysis_mode if user_state else "full",
            "demo_pattern_count": user_state.pattern_count if user_state else 0,
        }
        payload = {
            "user_id": user_id,
            "notification_type": scenario.notification_type.value,
            "notification_data": scenario.notification_data,
            "context": context,
        }

        # Apply overrides if any
        if overrides:
            if "urgency_boost" in overrides:
                payload["context"]["urgency_override"] = overrides["urgency_boost"]
            if "time_override" in overrides:
                payload["context"]["time_override"] = overrides["time_override"]
            if "channel_lock" in overrides:
                payload["context"]["channel_lock"] = overrides["channel_lock"]

        # Call the notification-intelligence agent (synchronous mode)
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{NOTIFICATION_AGENT_URL}/reasoners/route_notification",
                json=payload,
            )

            if response.status_code == 200:
                result = response.json()
                await demo_state.set_result(execution_id, result)
                await demo_state.update_execution_status(
                    execution_id, ExecutionStatus.COMPLETED
                )

                # Broadcast completion
                await manager.broadcast({
                    "type": "execution_completed",
                    "execution_id": execution_id,
                    "result": result,
                    "timestamp": datetime.now().isoformat(),
                })
            elif response.status_code == 202:
                # Async processing - results will come via SSE stream
                result = response.json()
                await manager.broadcast({
                    "type": "execution_processing",
                    "execution_id": execution_id,
                    "agent_execution_id": result.get("execution_id"),
                    "timestamp": datetime.now().isoformat(),
                })
                # Keep status as RUNNING - SSE events will update it
            else:
                error = f"Agent returned {response.status_code}: {response.text}"
                await demo_state.set_error(execution_id, error)
                await demo_state.update_execution_status(
                    execution_id, ExecutionStatus.FAILED
                )

                await manager.broadcast({
                    "type": "execution_failed",
                    "execution_id": execution_id,
                    "error": error,
                    "timestamp": datetime.now().isoformat(),
                })

    except Exception as e:
        error = str(e)
        await demo_state.set_error(execution_id, error)
        await demo_state.update_execution_status(execution_id, ExecutionStatus.FAILED)

        await manager.broadcast({
            "type": "execution_failed",
            "execution_id": execution_id,
            "error": error,
            "timestamp": datetime.now().isoformat(),
        })


@app.post("/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    Submit user feedback on a notification.

    This triggers the learning pipeline in the agent and
    updates the demo user's learning state.
    """
    # Update local demo state
    await demo_state.record_feedback(request.user_id, request.response)

    # Call the learning endpoint on the agent
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{NOTIFICATION_AGENT_URL}/reasoners/learn_from_feedback",
                json={
                    "user_id": request.user_id,
                    "notification_id": request.notification_id,
                    "notification_type": "demo",  # Simplified for demo
                    "user_response": request.response,
                },
            )

            learning_result = response.json() if response.status_code == 200 else None
    except Exception:
        learning_result = None

    # Get updated state
    state = demo_state.get_user_state(request.user_id)

    # Broadcast learning update
    await manager.broadcast({
        "type": "learning_update",
        "user_id": request.user_id,
        "response": request.response,
        "new_state": {
            "pattern_count": state.pattern_count if state else 0,
            "analysis_mode": state.analysis_mode if state else "full",
            "specialists_used": state.specialists_used if state else 5,
            "open_rate": state.open_rate if state else 0,
        },
        "learning_result": learning_result,
        "timestamp": datetime.now().isoformat(),
    })

    return {
        "status": "recorded",
        "user_id": request.user_id,
        "response": request.response,
        "new_pattern_count": state.pattern_count if state else 0,
        "new_analysis_mode": state.analysis_mode if state else "full",
    }


@app.get("/executions/{execution_id}")
async def get_execution(execution_id: str):
    """Get details of an execution including all events."""
    execution = demo_state.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    return {
        "id": execution.id,
        "user_id": execution.user_id,
        "scenario_id": execution.scenario_id,
        "status": execution.status.value,
        "started_at": execution.started_at.isoformat(),
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        "events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "agent_name": e.agent_name,
                "message": e.message,
                "tags": e.tags,
            }
            for e in execution.events
        ],
        "result": execution.result,
        "error": execution.error,
    }


@app.post("/reset")
async def reset_demo():
    """Reset all demo state."""
    demo_state.reset()
    return {"status": "reset", "message": "Demo state has been reset"}


# WebSocket endpoint
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """WebSocket endpoint for real-time agent events."""
    await websocket_endpoint(websocket)


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    # Use wsproto for WebSocket handling - better handles large headers
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        ws="wsproto",
    )
