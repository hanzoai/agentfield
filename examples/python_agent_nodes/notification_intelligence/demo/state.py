"""
In-memory state management for the demo.

Tracks:
- Active executions and their events
- User learning progress (simulated)
- Recent notification history
- Demo statistics
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
import asyncio


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentEvent:
    """A single event from agent execution."""
    timestamp: datetime
    event_type: str  # specialist_started, specialist_result, synthesis, decision, etc.
    agent_name: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class Execution:
    """Tracks a single notification decision execution."""
    id: str
    user_id: str
    scenario_id: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    events: List[AgentEvent] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class UserLearningState:
    """Simulated learning state for a demo user."""
    user_id: str
    pattern_count: int = 0
    analysis_mode: str = "full"  # full, moderate, streamlined
    notifications_sent: int = 0
    notifications_opened: int = 0
    notifications_ignored: int = 0
    channel_effectiveness: Dict[str, float] = field(default_factory=dict)

    @property
    def open_rate(self) -> float:
        total = self.notifications_opened + self.notifications_ignored
        return self.notifications_opened / total if total > 0 else 0.0

    @property
    def specialists_used(self) -> int:
        if self.analysis_mode == "full":
            return 5
        elif self.analysis_mode == "moderate":
            return 3
        return 2


class DemoState:
    """Global demo state manager."""

    def __init__(self):
        self._executions: Dict[str, Execution] = {}
        self._user_states: Dict[str, UserLearningState] = {}
        self._event_subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

        # Initialize demo users
        self._init_demo_users()

    def _init_demo_users(self):
        """Initialize demo users with different learning states."""
        # New user - full analysis
        self._user_states["user_new_001"] = UserLearningState(
            user_id="user_new_001",
            pattern_count=0,
            analysis_mode="full",
            notifications_sent=0
        )

        # Learning user - moderate analysis
        self._user_states["user_learning_002"] = UserLearningState(
            user_id="user_learning_002",
            pattern_count=4,
            analysis_mode="moderate",
            notifications_sent=12,
            notifications_opened=8,
            notifications_ignored=4,
            channel_effectiveness={"push": 0.75, "email": 0.45, "sms": 0.60}
        )

        # Power user - streamlined analysis
        self._user_states["user_power_003"] = UserLearningState(
            user_id="user_power_003",
            pattern_count=12,
            analysis_mode="streamlined",
            notifications_sent=45,
            notifications_opened=38,
            notifications_ignored=7,
            channel_effectiveness={"push": 0.85, "email": 0.52, "sms": 0.78, "app": 0.90}
        )

    async def create_execution(self, execution_id: str, user_id: str, scenario_id: str) -> Execution:
        """Create a new execution."""
        async with self._lock:
            execution = Execution(
                id=execution_id,
                user_id=user_id,
                scenario_id=scenario_id,
                status=ExecutionStatus.PENDING,
                started_at=datetime.now()
            )
            self._executions[execution_id] = execution
            return execution

    async def update_execution_status(self, execution_id: str, status: ExecutionStatus):
        """Update execution status."""
        async with self._lock:
            if execution_id in self._executions:
                self._executions[execution_id].status = status
                if status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED):
                    self._executions[execution_id].completed_at = datetime.now()

    async def add_event(self, execution_id: str, event: AgentEvent):
        """Add an event to an execution and notify subscribers."""
        async with self._lock:
            if execution_id in self._executions:
                self._executions[execution_id].events.append(event)

        # Notify all subscribers
        event_data = {
            "execution_id": execution_id,
            "event": {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "agent_name": event.agent_name,
                "message": event.message,
                "data": event.data,
                "tags": event.tags
            }
        }
        await self._broadcast_event(event_data)

    async def set_result(self, execution_id: str, result: Dict[str, Any]):
        """Set the final result of an execution."""
        async with self._lock:
            if execution_id in self._executions:
                self._executions[execution_id].result = result

    async def set_error(self, execution_id: str, error: str):
        """Set error for a failed execution."""
        async with self._lock:
            if execution_id in self._executions:
                self._executions[execution_id].error = error

    def get_execution(self, execution_id: str) -> Optional[Execution]:
        """Get an execution by ID."""
        return self._executions.get(execution_id)

    def get_user_state(self, user_id: str) -> Optional[UserLearningState]:
        """Get user learning state."""
        return self._user_states.get(user_id)

    def get_all_user_states(self) -> List[UserLearningState]:
        """Get all user learning states."""
        return list(self._user_states.values())

    async def record_feedback(self, user_id: str, response: str):
        """Record user feedback and update learning state."""
        async with self._lock:
            state = self._user_states.get(user_id)
            if state:
                state.notifications_sent += 1
                if response == "opened":
                    state.notifications_opened += 1
                elif response == "ignored":
                    state.notifications_ignored += 1
                elif response == "dismissed":
                    state.notifications_ignored += 1

                # Simulate learning from any explicit feedback signal
                state.pattern_count = min(state.pattern_count + 1, 20)

                # Update analysis mode based on patterns
                if state.pattern_count < 3:
                    state.analysis_mode = "full"
                elif state.pattern_count < 10:
                    state.analysis_mode = "moderate"
                else:
                    state.analysis_mode = "streamlined"

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to execution events."""
        queue = asyncio.Queue(maxsize=100)
        self._event_subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from execution events."""
        if queue in self._event_subscribers:
            self._event_subscribers.remove(queue)

    async def _broadcast_event(self, event_data: Dict[str, Any]):
        """Broadcast event to all subscribers."""
        for queue in self._event_subscribers:
            try:
                queue.put_nowait(event_data)
            except asyncio.QueueFull:
                pass  # Skip slow subscribers

    def reset(self):
        """Reset all state to initial values."""
        self._executions.clear()
        self._init_demo_users()


# Global state instance
demo_state = DemoState()
