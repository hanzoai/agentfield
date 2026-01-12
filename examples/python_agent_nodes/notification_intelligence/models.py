"""
Data models for Adaptive Multi-Agent Notification Intelligence

Minimal schemas (3-4 fields) optimized for smaller, cheaper LLMs.
Each schema represents a focused output from a specialist reasoner.
"""

from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict, Any, List


# ============================================
# SPECIALIST OUTPUT MODELS (3-4 fields max)
# ============================================

class UrgencyAssessment(BaseModel):
    """Urgency specialist output."""
    score: int = Field(ge=0, le=100, description="Urgency score")
    time_sensitive: bool = Field(description="Must act immediately?")
    reason: str = Field(description="Why this urgency level")


class ChannelRecommendation(BaseModel):
    """Channel specialist output."""
    channel: Literal["email", "sms", "push", "app"]
    confidence: float = Field(ge=0.0, le=1.0)
    backup: Optional[str] = Field(None, description="Alternative channel")


class UserStateAnalysis(BaseModel):
    """User state specialist output."""
    engagement_likelihood: float = Field(ge=0.0, le=1.0)
    attention_state: Literal["active", "busy", "offline", "unknown"]
    preference_signal: str = Field(description="Key preference insight")


class TimingRecommendation(BaseModel):
    """Timing specialist output."""
    when: Literal["now", "delay", "batch", "skip"]
    delay_until: Optional[str] = Field(None, description="ISO timestamp if delaying")
    rationale: str = Field(description="Timing reasoning")


class ContextSignals(BaseModel):
    """Context specialist output."""
    priority_indicator: int = Field(ge=0, le=100)
    content_urgency: Literal["critical", "high", "medium", "low"]
    situational_factor: str = Field(description="Key context insight")


class NotificationAction(BaseModel):
    """Final synthesized decision."""
    deliver: Literal["now", "delay", "batch", "skip"]
    channel: Literal["email", "sms", "push", "app"]
    priority: int = Field(ge=0, le=100)
    reasoning: str = Field(description="Decision explanation")


# ============================================
# LEARNING MODELS (3-4 fields max)
# ============================================

class LearningInsight(BaseModel):
    """Single insight from user feedback."""
    pattern: str = Field(description="What we learned")
    strength: float = Field(ge=0.0, le=1.0, description="Confidence in insight")
    applies_to: str = Field(description="Notification types this affects")


class BehaviorPattern(BaseModel):
    """Behavior pattern insight."""
    pattern: str
    strength: float = Field(ge=0.0, le=1.0)
    applies_to: str


class ChannelInsight(BaseModel):
    """Channel effectiveness insight."""
    pattern: str
    strength: float = Field(ge=0.0, le=1.0)
    applies_to: str


class PreferenceSignal(BaseModel):
    """User preference signal."""
    pattern: str
    strength: float = Field(ge=0.0, le=1.0)
    applies_to: str


# ============================================
# MEMORY STATE MODELS
# ============================================

class UserPreferenceModel(BaseModel):
    """
    User-specific learned patterns stored in actor memory.
    This model grows smarter over time with each interaction.
    """
    learned_patterns: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Extracted patterns from user feedback"
    )
    channel_effectiveness: Dict[str, float] = Field(
        default_factory=dict,
        description="Channel engagement rates"
    )
    sample_size: int = Field(
        default=0,
        description="Number of feedback samples"
    )


class GlobalPatternModel(BaseModel):
    """
    System-wide patterns stored in global memory.
    Represents cross-user insights and typical behaviors.
    """
    common_action: str = Field(description="Most common action for this type")
    typical_channel: str = Field(description="Most effective channel")
    confidence: float = Field(ge=0.0, le=1.0)


# ============================================
# META-LEARNING MODELS (3-4 fields max)
# ============================================

class RouteStrategy(BaseModel):
    """Meta-learning routing strategy."""
    prefer: Literal["full", "moderate", "streamlined"]
    threshold: int = Field(description="Pattern count threshold")
    rationale: str = Field(description="Why this strategy")


class OptimizationInsight(BaseModel):
    """System optimization recommendation."""
    change: str = Field(description="What to change")
    impact: float = Field(ge=0.0, le=1.0, description="Expected improvement")
    priority: Literal["high", "medium", "low"]
