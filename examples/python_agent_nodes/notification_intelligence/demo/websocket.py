"""
WebSocket bridge for real-time agent events.

Connects to AgentField SSE endpoints and forwards events
to frontend WebSocket clients.
"""

import os
import json
import asyncio
import httpx
from datetime import datetime
from typing import Set, Optional
from fastapi import WebSocket, WebSocketDisconnect

from state import demo_state, AgentEvent


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept and track a new connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        """Remove a connection."""
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        msg_type = message.get('type', 'unknown')
        agent = message.get('agent_name', 'none')
        print(f"[Manager] broadcast called: type={msg_type}, agent={agent}, connections={len(self.active_connections)}", flush=True)

        if not self.active_connections:
            print(f"[Manager] No connections, skipping", flush=True)
            return

        data = json.dumps(message)
        async with self._lock:
            dead_connections = set()
            for i, connection in enumerate(self.active_connections):
                try:
                    await connection.send_text(data)
                    print(f"[Manager] Sent to connection {i}: {msg_type}/{agent}", flush=True)
                except Exception as e:
                    print(f"[Manager] Failed to send to connection {i}: {e}", flush=True)
                    dead_connections.add(connection)

            # Clean up dead connections
            self.active_connections -= dead_connections


# Global connection manager
manager = ConnectionManager()


class AgentFieldSSEBridge:
    """
    Bridges AgentField SSE events to WebSocket clients.

    Subscribes to execution events and notes from AgentField,
    parses them, and broadcasts to connected WebSocket clients.
    """

    def __init__(self, agentfield_url: str):
        self.agentfield_url = agentfield_url.rstrip("/")
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._current_execution_id: Optional[str] = None

    async def start(self):
        """Start listening to AgentField events."""
        print(f"[SSE] start() called, already running: {self._running}", flush=True)
        if self._running:
            return
        self._running = True
        print(f"[SSE] Creating listen loop task...", flush=True)
        self._task = asyncio.create_task(self._listen_loop())
        print(f"[SSE] Listen loop task created", flush=True)

    async def stop(self):
        """Stop listening."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def set_execution_id(self, execution_id: str):
        """Set the current execution ID to filter events."""
        self._current_execution_id = execution_id

    async def _listen_loop(self):
        """Main loop that listens to SSE events."""
        print(f"[SSE] _listen_loop started, running: {self._running}", flush=True)
        while self._running:
            try:
                await self._connect_and_listen()
            except Exception as e:
                print(f"[SSE] connection error: {e}", flush=True)
                await asyncio.sleep(2)  # Reconnect delay

    async def _connect_and_listen(self):
        """Connect to SSE endpoint and process events."""
        url = f"{self.agentfield_url}/api/ui/v1/executions/events"
        print(f"[SSE] Connecting to: {url}", flush=True)

        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", url) as response:
                print(f"[SSE] Connected, status: {response.status_code}", flush=True)
                async for line in response.aiter_lines():
                    print(f"[SSE] Line: {line[:100] if line else '(empty)'}", flush=True)
                    if not self._running:
                        break

                    if line.startswith("data:"):
                        data_str = line[5:].strip()
                        if data_str:
                            try:
                                event_data = json.loads(data_str)
                                await self._process_event(event_data)
                            except json.JSONDecodeError:
                                pass

    async def _process_event(self, event_data: dict):
        """Process an incoming SSE event."""
        event_type = event_data.get("type", "")
        execution_id = event_data.get("execution_id")

        # Debug: log all incoming SSE events
        print(f"[SSE] Received event: type={event_type}, exec_id={execution_id}, data_keys={list(event_data.keys())}", flush=True)

        # For demo simplicity, forward all events (no filtering)

        # Map SSE event to demo event
        demo_event = None

        if event_type == "execution_started":
            demo_event = {
                "type": "execution_started",
                "execution_id": execution_id,
                "timestamp": datetime.now().isoformat()
            }

        elif event_type == "workflow_note_added":
            note = event_data.get("data", {}).get("note", {})
            message = note.get("message", "")
            tags = note.get("tags", [])

            # Determine agent/specialist from tags or message
            agent_name = self._extract_agent_name(message, tags)
            event_type_name = self._determine_event_type(message, tags)

            agent_event = AgentEvent(
                timestamp=datetime.now(),
                event_type=event_type_name,
                agent_name=agent_name,
                message=message,
                data=note,
                tags=tags
            )

            # Store in demo state
            if execution_id:
                await demo_state.add_event(execution_id, agent_event)

            demo_event = {
                "type": "agent_event",
                "execution_id": execution_id,
                "agent_name": agent_name,
                "event_type": event_type_name,
                "message": message,
                "tags": tags,
                "timestamp": datetime.now().isoformat()
            }

        elif event_type == "execution_completed":
            demo_event = {
                "type": "execution_completed",
                "execution_id": execution_id,
                "result": event_data.get("data", {}),
                "timestamp": datetime.now().isoformat()
            }

        elif event_type == "execution_failed":
            demo_event = {
                "type": "execution_failed",
                "execution_id": execution_id,
                "error": event_data.get("error", "Unknown error"),
                "timestamp": datetime.now().isoformat()
            }

        if demo_event:
            print(f"[SSE->WS] Broadcasting: type={demo_event.get('type')}, agent={demo_event.get('agent_name')}")
            await manager.broadcast(demo_event)

    def _extract_agent_name(self, message: str, tags: list) -> str:
        """Extract agent/specialist name from message or tags."""
        # Check tags first
        if "specialist" in tags:
            # Parse emoji prefix to determine specialist
            if message.startswith("⚡"):
                return "urgency"
            elif message.startswith("📱"):
                return "channel"
            elif message.startswith("👤"):
                return "user_state"
            elif message.startswith("⏰"):
                return "timing"
            elif message.startswith("🔍"):
                return "context"

        if "synthesis" in tags:
            return "synthesis"
        if "orchestration" in tags:
            return "orchestration"
        if "parallel" in tags:
            return "parallel"
        if "learning" in tags:
            if "behavior" in tags:
                return "behavior_learner"
            elif "channel" in tags:
                return "channel_learner"
            elif "preference" in tags:
                return "preference_learner"
            return "learning"

        return "system"

    def _determine_event_type(self, message: str, tags: list) -> str:
        """Determine the event type from message/tags."""
        if "specialist" in tags:
            return "specialist_result"
        if "synthesis" in tags:
            if "Synthesizing" in message:
                return "synthesis_started"
            return "synthesis_result"
        if "orchestration" in tags:
            return "routing_decision"
        if "parallel" in tags:
            if "Launching" in message:
                return "specialists_started"
            elif "complete" in message.lower():
                return "specialists_completed"
        if "learning" in tags:
            return "learning_insight"

        return "note"


# Create bridge instance (URL configured at runtime)
sse_bridge: Optional[AgentFieldSSEBridge] = None


def init_sse_bridge(agentfield_url: str) -> AgentFieldSSEBridge:
    """Initialize the SSE bridge with AgentField URL."""
    global sse_bridge
    print(f"[SSE] init_sse_bridge called with URL: {agentfield_url}", flush=True)
    sse_bridge = AgentFieldSSEBridge(agentfield_url)
    return sse_bridge


async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for frontend clients.

    Clients connect here to receive real-time agent events.
    """
    await manager.connect(websocket)
    try:
        # Also subscribe to demo state events
        queue = demo_state.subscribe()

        # Create task to forward demo state events
        async def forward_state_events():
            while True:
                try:
                    event = await queue.get()
                    await websocket.send_json(event)
                except Exception:
                    break

        forward_task = asyncio.create_task(forward_state_events())

        try:
            # Keep connection alive and handle client messages
            while True:
                data = await websocket.receive_text()
                # Handle client messages (e.g., ping/pong)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except json.JSONDecodeError:
                    pass
        finally:
            forward_task.cancel()
            demo_state.unsubscribe(queue)

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)
