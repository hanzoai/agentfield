"""
Adaptive Multi-Agent Notification Intelligence Reasoners

Visual multi-agent orchestration with parallel specialist analysis.
Creates impressive workflow graphs while maintaining production efficiency.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List
from agentfield import AgentRouter
from models import (
    UrgencyAssessment,
    ChannelRecommendation,
    UserStateAnalysis,
    TimingRecommendation,
    ContextSignals,
    NotificationAction,
    BehaviorPattern,
    ChannelInsight,
    PreferenceSignal,
    UserPreferenceModel,
)

router = AgentRouter(tags=["notification-intelligence"])


# ============================================
# TIER 1: SPECIALIST REASONERS
# Each creates a visible node in workflow graph
# ============================================

@router.reasoner()
async def analyze_urgency(
    notification_type: str,
    notification_data: dict,
    user_context: dict
) -> dict:
    """
    Urgency specialist: Analyzes time-sensitivity and priority signals.

    Evaluates how quickly this notification requires user attention
    based on notification content, user tier, and temporal context.
    Forms one branch of the parallel analysis star in workflow graph.
    """

    # Extract key data points for urgency assessment
    cart_value = notification_data.get("cart_value", 0)
    expires_hours = notification_data.get("expires_in_hours", 24)
    abandoned_mins = notification_data.get("abandoned_minutes_ago", 0)
    discount_percent = notification_data.get("discount_percent", 0)
    stock_qty = notification_data.get("stock_quantity", 100)
    shipping_status = notification_data.get("status", "")

    result = await router.ai(
        f"""Notification Type: {notification_type}
Data: {notification_data}
Context: {user_context}

URGENCY SCORING RULES BY TYPE:

ABANDONED_CART:
- Cart value >$150 AND abandoned 30-90 mins: score 75-90, time_sensitive=true
- Cart value $50-150 AND abandoned 30-90 mins: score 55-75
- Cart value <$50 OR abandoned <20 mins OR >3 hours: score 30-50, time_sensitive=false
- Current: value=${cart_value}, abandoned={abandoned_mins} mins ago

FLASH_SALE:
- Expires in <3 hours AND discount >30%: score 85-95, time_sensitive=true
- Expires in 3-6 hours: score 65-80
- Expires in >12 hours OR discount <20%: score 35-55, time_sensitive=false
- Current: expires in {expires_hours} hours, {discount_percent}% off

BACK_IN_STOCK:
- Low stock (<20 units) AND wishlisted: score 65-80
- Normal stock OR not wishlisted: score 40-55, time_sensitive=false
- Current: {stock_qty} units available

PRICE_DROP:
- Discount >30% AND user previously carted: score 70-85
- Moderate discount (15-30%): score 50-65
- Small discount (<15%): score 30-45, time_sensitive=false
- Current: {discount_percent}% off

SHIPPING_UPDATE:
- "out_for_delivery": score 70-85, time_sensitive=true (action may be needed)
- "delayed": score 60-75 (user should know)
- "shipped" or "delivered": score 25-40, time_sensitive=false (informational)
- Current status: {shipping_status}

Based on the rules above, what is the urgency assessment?""",
        schema=UrgencyAssessment
    )

    router.note(f"⚡ Urgency: {result.score}/100 ({'immediate' if result.time_sensitive else 'flexible'}) | {result.reason}",
                tags=["specialist", "urgency"])

    return result.model_dump()


@router.reasoner()
async def analyze_channel_fit(
    notification_type: str,
    user_id: str,
    time_context: dict
) -> dict:
    """
    Channel specialist: Determines optimal delivery channel.

    Analyzes learned channel effectiveness from user history and
    current timing to recommend best delivery mechanism. Uses
    actor memory to retrieve per-user channel engagement patterns.
    """

    # Retrieve learned channel effectiveness
    user_mem = router.memory.actor(user_id)
    channel_stats = await user_mem.get("channel_effectiveness", default={
        "email": 0.5, "sms": 0.5, "push": 0.5, "app": 0.5
    })

    current_hour = time_context.get("current_hour_user_timezone", 12)

    result = await router.ai(
        f"""Notification Type: {notification_type}
Time Context: {time_context}
Current hour: {current_hour} (0-23)
Learned channel effectiveness: {channel_stats}

CHANNEL SELECTION RULES:

ABANDONED_CART:
- Primary: "push" (immediate visibility, high engagement)
- Backup: "email" (for details, longer shelf life)
- Confidence: 0.8-0.9 for push during day hours

FLASH_SALE:
- Time-sensitive: "push" primary (immediate action needed)
- If discount >40%: consider "sms" as backup (high priority)
- Confidence: 0.75-0.9 based on time remaining

BACK_IN_STOCK:
- Primary: "email" (allows browsing details, not urgent)
- If low stock: "push" for urgency
- Confidence: 0.6-0.8

PRICE_DROP:
- Primary: "push" (quick action opportunity)
- Backup: "email" (comparison details)
- Confidence: 0.7-0.85

SHIPPING_UPDATE:
- "out_for_delivery": "push" primary (action may be needed)
- "shipped": "app" or "email" (informational)
- "delivered": "app" primary (just FYI)
- Confidence: varies by status 0.6-0.9

TIME MODIFIERS:
- Night hours (22-7): prefer "email" over "push" (less intrusive)
- Business hours (9-18): "push" is acceptable
- Peak engagement hours (lunch, evening): higher confidence

Best channel recommendation?""",
        schema=ChannelRecommendation
    )

    backup_info = f", backup: {result.backup}" if result.backup else ""
    router.note(f"📱 Channel: {result.channel} (confidence: {result.confidence:.2f}{backup_info})",
                tags=["specialist", "channel"])

    return result.model_dump()


@router.reasoner()
async def analyze_user_state(
    user_id: str,
    notification_type: str,
    user_context: dict
) -> dict:
    """
    User state specialist: Analyzes user engagement patterns and preferences.

    Examines learned user patterns to predict engagement likelihood
    and current attention state. Leverages historical interaction
    data stored in actor memory.
    """

    user_mem = router.memory.actor(user_id)
    patterns = await user_mem.get("learned_patterns", default=[])

    # Extract relevant patterns
    relevant = [p for p in patterns if notification_type in p.get("applies_to", "")][:3]

    # Extract fatigue signals from context
    notifications_today = user_context.get("notifications_sent_today", 0)
    ignored_recent = user_context.get("recent_notifications_ignored", 0)
    engagement = user_context.get("user_engagement_level", "medium")

    result = await router.ai(
        f"""User learned patterns: {relevant}
Notification: {notification_type}
Notifications sent today: {notifications_today}
Recent notifications ignored: {ignored_recent}
User engagement level: {engagement}

FATIGUE RULES:
- If ignored 3+: attention_state should be "busy", engagement_likelihood < 0.3
- If 5+ notifications today: engagement_likelihood should be low
- If engagement is "low": engagement_likelihood < 0.4

User state?""",
        schema=UserStateAnalysis
    )

    router.note(f"👤 User: {result.attention_state}, engagement {result.engagement_likelihood:.0%} | {result.preference_signal}",
                tags=["specialist", "user-state"])

    return result.model_dump()


@router.reasoner()
async def analyze_timing_window(
    time_context: dict,
    urgency_score: int,
    user_timezone: str
) -> dict:
    """
    Timing specialist: Determines optimal send timing.

    Considers urgency level, user timezone, and learned timing
    patterns to recommend when notification should be delivered.
    Balances immediacy with user convenience.
    """

    # Get global timing patterns
    timing_patterns = await router.memory.global_scope.get(
        "optimal_timing_patterns",
        default={"peak_hours": [9, 10, 14, 15, 19], "avoid_hours": [0, 1, 2, 3, 4, 5, 6, 7]}
    )

    # Extract key signals for timing decision
    current_hour = time_context.get("current_hour_user_timezone", 12)
    user_browsing = time_context.get("user_currently_browsing", False)

    # Pre-compute time of day to avoid LLM math errors
    is_night = 0 <= current_hour <= 7
    is_peak = current_hour in timing_patterns.get("peak_hours", [9, 10, 14, 15, 19])

    # Deterministic timing decision - no LLM involvement for reliability
    if is_night:
        when = "delay"
        # Delay until 8 AM
        now = datetime.now()
        morning = now.replace(hour=8, minute=0, second=0, microsecond=0)
        if morning <= now:
            morning += timedelta(days=1)
        delay_until = morning.isoformat()
        rationale = f"Hour {current_hour} is during night hours (0-7). Delaying until morning at 8 AM for better engagement."
    elif user_browsing and urgency_score < 70:
        when = "delay"
        delay_until = None
        rationale = f"User is currently browsing and urgency ({urgency_score}) is below 70. Delay to avoid interrupting their session."
    elif not user_browsing and urgency_score >= 50:
        when = "now"
        delay_until = None
        peak_note = " This is a peak engagement hour." if is_peak else ""
        rationale = f"User is not browsing and urgency ({urgency_score}) is high enough to re-engage them.{peak_note} Send now."
    elif urgency_score < 30:
        when = "batch"
        delay_until = None
        rationale = f"Low urgency ({urgency_score}). Can be batched with other notifications."
    else:
        when = "now"
        delay_until = None
        rationale = f"Hour {current_hour} is within acceptable range (8-22). Sending now."

    delay_info = f" (until {delay_until})" if delay_until else ""
    router.note(f"⏰ Timing: {when}{delay_info} | {rationale}",
                tags=["specialist", "timing"])

    return {"when": when, "delay_until": delay_until, "rationale": rationale}


@router.reasoner()
async def analyze_context_signals(
    notification_data: dict,
    user_tier: str,
    current_time: str
) -> dict:
    """
    Context specialist: Extracts implicit priority signals.

    Analyzes notification content and situational factors to
    identify urgency indicators that may not be explicit.
    Considers user tier and temporal context.
    """

    # Extract data for context analysis
    cart_value = notification_data.get("cart_value", 0)
    item_price = notification_data.get("item_price", 0) or notification_data.get("new_price", 0)
    discount = notification_data.get("discount_percent", 0)
    stock_qty = notification_data.get("stock_quantity", 100)
    expires_hours = notification_data.get("expires_in_hours", 24)

    result = await router.ai(
        f"""Notification data: {notification_data}
User tier: {user_tier}
Current time: {current_time}

CONTEXT PRIORITY RULES:

VALUE-BASED SIGNALS:
- High value (cart >$100 or item >$200): priority_indicator 70-90, content_urgency="high"
- Medium value ($50-100): priority_indicator 50-70, content_urgency="medium"
- Low value (<$50): priority_indicator 30-50, content_urgency="low"
- Current value context: cart=${cart_value}, item=${item_price}

USER TIER MODIFIERS:
- Gold tier: +10 to priority (valuable customer)
- Silver tier: +5 to priority
- Standard: no modifier

TIME-SENSITIVE SIGNALS:
- Sale expiring <3 hours: content_urgency="critical", priority 80+
- Sale expiring <12 hours: content_urgency="high"
- Low stock (<20): adds urgency
- Current: expires in {expires_hours}h, stock={stock_qty}

DISCOUNT SIGNALS:
- >40% off: content_urgency="high", "exceptional discount opportunity"
- 20-40% off: content_urgency="medium", "good value proposition"
- <20% off: content_urgency="low", "modest savings"
- Current discount: {discount}%

SITUATIONAL FACTORS (choose one that best describes the situation):
- "Limited time opportunity - action needed soon"
- "High-value cart at risk - recovery priority"
- "Wishlist item available - strong user intent signal"
- "Routine notification - no special urgency"
- "VIP customer - prioritize engagement"

What are the implicit priority signals?""",
        schema=ContextSignals
    )

    router.note(f"🔍 Context: {result.content_urgency} priority ({result.priority_indicator}/100) | {result.situational_factor}",
                tags=["specialist", "context"])

    return result.model_dump()


# ============================================
# TIER 2: SYNTHESIS REASONER
# Convergence node in workflow graph
# ============================================

@router.reasoner()
async def synthesize_decision(
    urgency_analysis: dict,
    channel_analysis: dict,
    user_state_analysis: dict,
    timing_analysis: dict,
    context_signals: dict,
    user_context: dict
) -> dict:
    """
    Synthesis orchestrator: Merges all specialist analyses.

    Creates the convergence point in workflow graph where all
    parallel specialist branches merge. Weighs each perspective
    to produce final unified decision.
    """

    # Get fatigue signals from user context
    notifs_today = user_context.get("notifications_sent_today", 0)
    ignored = user_context.get("recent_notifications_ignored", 0)
    engagement = user_context.get("user_engagement_level", "medium")
    hour = user_context.get("current_hour_user_timezone", 12)
    browsing = user_context.get("user_currently_browsing", False)

    # Pre-compute time conditions to avoid LLM math errors
    is_outside_hours = hour < 8 or hour > 22
    should_skip = ignored >= 3 or notifs_today >= 5 or engagement == "low"
    should_delay = is_outside_hours or browsing

    router.note(f"🧩 Synthesizing: hour={hour}, ignored={ignored}, notifs={notifs_today}, engagement={engagement}, browsing={browsing}",
                tags=["synthesis"])

    final = await router.ai(
        f"""Specialist Analyses:

Urgency: {urgency_analysis}
Channel: {channel_analysis}
User State: {user_state_analysis}
Timing: {timing_analysis}
Context: {context_signals}

FATIGUE SIGNALS (from user context):
- Notifications sent today: {notifs_today}
- Recent notifications ignored: {ignored}
- User engagement level: {engagement}
- Current hour in user timezone: {hour}
- User currently browsing site: {browsing}

PRE-COMPUTED CONDITIONS (trust these boolean values):
- SHOULD_SKIP = {should_skip} (ignored >= 3 OR notifs >= 5 OR engagement low)
- SHOULD_DELAY = {should_delay} (hour outside 8-22 OR browsing)
- IS_OUTSIDE_HOURS = {is_outside_hours} (hour {hour} is {'NOT ' if not is_outside_hours else ''}outside 8-22 range)

MANDATORY DECISION RULES - FOLLOW THESE EXACTLY:
1. IF SHOULD_SKIP == True THEN deliver="skip"
2. ELSE IF SHOULD_DELAY == True THEN deliver="delay"
3. ELSE IF urgency < 40 AND notifs_today >= 2 THEN deliver="batch"
4. ELSE deliver="now"

Current: SHOULD_SKIP={should_skip}, SHOULD_DELAY={should_delay}, hour={hour}

Based on these pre-computed values, which rule applies?

Synthesize final notification decision:""",
        schema=NotificationAction
    )

    router.note(f"✨ Final: {final.deliver} via {final.channel} (priority {final.priority}/100)",
                tags=["synthesis", "decision"])

    return final.model_dump()


# ============================================
# TIER 3: ADAPTIVE ORCHESTRATORS
# Control which specialists are invoked
# ============================================

@router.reasoner()
async def route_notification(
    user_id: str,
    notification_type: str,
    notification_data: dict,
    context: dict
) -> dict:
    """
    Adaptive orchestrator: Routes to appropriate analysis depth.

    Determines orchestration strategy based on user learning maturity:
    - New users (0-2 patterns): Full 5-specialist analysis
    - Learning users (3-9 patterns): Moderate 3-specialist analysis
    - Confident users (10+ patterns): Streamlined 2-specialist analysis

    Creates progressively simpler workflow graphs as system gains
    confidence in user understanding.
    """

    # Store context in workflow memory (guard against None memory in edge cases)
    if router.memory is not None:
        await router.memory.set("notification_type", notification_type)
        await router.memory.set("user_context", context)

    # Demo-only override: allow upstream callers (the UI demo) to force
    # orchestration depth so the graph clearly shows full → moderate → streamlined
    # without requiring pre-seeded long-term memory for the demo users.
    demo_depth = context.get("demo_analysis_depth")
    demo_pattern_count = context.get("demo_pattern_count")
    if demo_depth in ("full", "moderate", "streamlined"):
        try:
            pattern_count = int(demo_pattern_count) if demo_pattern_count is not None else 0
        except Exception:
            pattern_count = 0

        router.note(
            f"🧪 Demo override: {demo_depth.upper()} analysis ({pattern_count} patterns)",
            tags=["orchestration", "demo", demo_depth],
        )

        if demo_depth == "full":
            decision = await orchestrate_full_analysis(
                user_id, notification_type, notification_data, context
            )
        elif demo_depth == "moderate":
            decision = await orchestrate_moderate_analysis(
                user_id, notification_type, notification_data, context
            )
        else:
            decision = await orchestrate_streamlined_analysis(
                user_id, notification_type, notification_data, context
            )

        if router.memory is not None:
            await router.memory.set("final_decision", decision)
        return {
            "decision": decision,
            "pattern_count": pattern_count,
            "analysis_depth": demo_depth,
        }

    # Get user's learning maturity
    if router.memory is not None:
        user_mem = router.memory.actor(user_id)
        patterns = await user_mem.get("learned_patterns", default=[])
    else:
        patterns = []
    pattern_count = len(patterns)

    router.note(f"📊 User learning maturity: {pattern_count} patterns", tags=["orchestration"])

    # Adaptive routing based on maturity
    if pattern_count < 3:
        # NEW USER - Full visual analysis
        router.note("🌟 Routing: FULL analysis (5 specialists) - learning phase",
                   tags=["orchestration", "full"])
        decision = await orchestrate_full_analysis(
            user_id, notification_type, notification_data, context
        )

    elif pattern_count < 10:
        # LEARNING USER - Moderate analysis
        router.note("⚡ Routing: MODERATE analysis (3 specialists) - maturing",
                   tags=["orchestration", "moderate"])
        decision = await orchestrate_moderate_analysis(
            user_id, notification_type, notification_data, context
        )

    else:
        # CONFIDENT - Streamlined analysis
        router.note("🎯 Routing: STREAMLINED analysis (2 specialists) - confident",
                   tags=["orchestration", "streamlined"])
        decision = await orchestrate_streamlined_analysis(
            user_id, notification_type, notification_data, context
        )

    # Store decision for learning
    if router.memory is not None:
        await router.memory.set("final_decision", decision)

    return {
        "decision": decision,
        "pattern_count": pattern_count,
        "analysis_depth": "full" if pattern_count < 3 else "moderate" if pattern_count < 10 else "streamlined"
    }


@router.reasoner()
async def orchestrate_full_analysis(
    user_id: str,
    notification_type: str,
    notification_data: dict,
    context: dict
) -> dict:
    """
    Full 5-specialist parallel orchestration.

    Launches all specialist reasoners in parallel, creating an
    impressive star-pattern workflow graph with 5 branches
    converging to synthesis. Used for new users or complex cases
    where maximum insight is valuable.

    Graph pattern: 5 parallel specialists → 1 synthesis
    AI calls: 6 total (5 parallel + 1 synthesis)
    """

    router.note("🔄 Launching 5 parallel specialists...", tags=["parallel"])

    # Launch ALL specialists in parallel (creates star graph)
    urgency_task = router.app.call(
        "notification-intelligence.analyze_urgency",
        notification_type=notification_type,
        notification_data=notification_data,
        user_context=context
    )

    channel_task = router.app.call(
        "notification-intelligence.analyze_channel_fit",
        notification_type=notification_type,
        user_id=user_id,
        time_context={"current_time": context["current_time"], "timezone": context["user_timezone"]}
    )

    user_state_task = router.app.call(
        "notification-intelligence.analyze_user_state",
        user_id=user_id,
        notification_type=notification_type,
        user_context=context
    )

    timing_task = router.app.call(
        "notification-intelligence.analyze_timing_window",
        time_context={
            "current_time": context.get("current_time"),
            "current_hour_user_timezone": context.get("current_hour_user_timezone", 12),
            "user_currently_browsing": context.get("user_currently_browsing", False),
        },
        urgency_score=85,  # Placeholder, will be refined
        user_timezone=context.get("user_timezone", "America/New_York")
    )

    context_task = router.app.call(
        "notification-intelligence.analyze_context_signals",
        notification_data=notification_data,
        user_tier=context["user_tier"],
        current_time=context["current_time"]
    )

    # Wait for all parallel analyses
    urgency, channel, user_state, timing, ctx_signals = await asyncio.gather(
        urgency_task, channel_task, user_state_task, timing_task, context_task
    )

    router.note("✅ All 5 specialists complete", tags=["parallel"])

    # Synthesize (creates convergence node)
    final_decision = await router.app.call(
        "notification-intelligence.synthesize_decision",
        urgency_analysis=urgency,
        channel_analysis=channel,
        user_state_analysis=user_state,
        timing_analysis=timing,
        context_signals=ctx_signals,
        user_context=context
    )

    return final_decision


@router.reasoner()
async def orchestrate_moderate_analysis(
    user_id: str,
    notification_type: str,
    notification_data: dict,
    context: dict
) -> dict:
    """
    Moderate 3-specialist parallel orchestration.

    Balanced approach using core specialists: urgency, channel, timing.
    Creates clear workflow graph while reducing AI cost by 40%.

    Graph pattern: 3 parallel specialists → 1 synthesis
    AI calls: 4 total (3 parallel + 1 synthesis)
    """

    router.note("🔄 Launching 3 core specialists...", tags=["parallel"])

    # Launch core specialists in parallel
    urgency_task = router.app.call(
        "notification-intelligence.analyze_urgency",
        notification_type=notification_type,
        notification_data=notification_data,
        user_context=context
    )

    channel_task = router.app.call(
        "notification-intelligence.analyze_channel_fit",
        notification_type=notification_type,
        user_id=user_id,
        time_context={"current_time": context["current_time"], "timezone": context["user_timezone"]}
    )

    timing_task = router.app.call(
        "notification-intelligence.analyze_timing_window",
        time_context={
            "current_time": context.get("current_time"),
            "current_hour_user_timezone": context.get("current_hour_user_timezone", 12),
            "user_currently_browsing": context.get("user_currently_browsing", False),
        },
        urgency_score=75,
        user_timezone=context.get("user_timezone", "America/New_York")
    )

    urgency, channel, timing = await asyncio.gather(
        urgency_task, channel_task, timing_task
    )

    router.note("✅ Core specialists complete", tags=["parallel"])

    # Pre-compute conditions to avoid LLM math errors
    hour = context.get('current_hour_user_timezone', 12)
    ignored = context.get('recent_notifications_ignored', 0)
    notifs = context.get('notifications_sent_today', 0)
    engagement = context.get('user_engagement_level', 'medium')
    browsing = context.get('user_currently_browsing', False)

    should_skip = ignored >= 3 or notifs >= 5 or engagement == "low"
    is_outside_hours = hour < 8 or hour > 22
    should_delay = is_outside_hours or browsing

    # Simplified synthesis with decision rules
    final = await router.ai(
        f"""Urgency: {urgency}
Channel: {channel}
Timing: {timing}
User context: notifications_today={notifs}, ignored={ignored}, engagement={engagement}, hour={hour}, browsing={browsing}

PRE-COMPUTED (trust these): SHOULD_SKIP={should_skip}, SHOULD_DELAY={should_delay}
Hour {hour} is {'OUTSIDE' if is_outside_hours else 'INSIDE'} acceptable range (8-22).

DECISION RULES:
- IF SHOULD_SKIP=True THEN skip
- ELSE IF SHOULD_DELAY=True THEN delay
- ELSE deliver now

Final decision?""",
        schema=NotificationAction
    )

    router.note(f"✨ Decision: {final.deliver} via {final.channel}", tags=["synthesis"])

    return final.model_dump()


@router.reasoner()
async def orchestrate_streamlined_analysis(
    user_id: str,
    notification_type: str,
    notification_data: dict,
    context: dict
) -> dict:
    """
    Streamlined 2-specialist orchestration.

    Minimal orchestration for well-understood users. Uses only
    urgency and channel analysis, reducing AI cost by 67%.

    Graph pattern: 2 parallel specialists → direct synthesis
    AI calls: 3 total (2 parallel + 1 synthesis)
    """

    router.note("🔄 Launching streamlined analysis...", tags=["parallel"])

    # Just urgency and channel
    urgency_task = router.app.call(
        "notification-intelligence.analyze_urgency",
        notification_type=notification_type,
        notification_data=notification_data,
        user_context=context
    )

    channel_task = router.app.call(
        "notification-intelligence.analyze_channel_fit",
        notification_type=notification_type,
        user_id=user_id,
        time_context={"current_time": context["current_time"], "timezone": context["user_timezone"]}
    )

    urgency, channel = await asyncio.gather(urgency_task, channel_task)

    router.note("✅ Streamlined complete", tags=["parallel"])

    # Pre-compute conditions to avoid LLM math errors
    hour = context.get('current_hour_user_timezone', 12)
    ignored = context.get('recent_notifications_ignored', 0)
    notifs = context.get('notifications_sent_today', 0)
    browsing = context.get('user_currently_browsing', False)

    should_skip = ignored >= 3 or notifs >= 5
    is_outside_hours = hour < 8 or hour > 22
    should_delay = is_outside_hours or browsing

    # Quick synthesis with decision rules
    final = await router.ai(
        f"""Urgency: {urgency}
Channel: {channel}
Context: notifications_today={notifs}, ignored={ignored}, hour={hour}, browsing={browsing}

PRE-COMPUTED (trust these): SHOULD_SKIP={should_skip}, SHOULD_DELAY={should_delay}
Hour {hour} is {'OUTSIDE' if is_outside_hours else 'INSIDE'} acceptable range (8-22).

RULES: IF SHOULD_SKIP=True THEN skip. ELSE IF SHOULD_DELAY=True THEN delay. ELSE NOW.

Decision?""",
        schema=NotificationAction
    )

    return final.model_dump()


# ============================================
# TIER 4: LEARNING REASONERS
# Extract insights from user feedback
# ============================================

@router.reasoner()
async def learn_from_feedback(
    user_id: str,
    notification_id: str,
    notification_type: str,
    user_response: dict
) -> dict:
    """
    Learning orchestrator: Extracts actionable insights from user feedback.

    Launches parallel insight extraction creating a separate learning
    workflow graph. Each specialist extracts a different type of pattern:
    behavior, channel effectiveness, preference signals.

    Graph pattern: 3 parallel learning specialists → pattern storage
    AI calls: 3 total (all parallel)
    """

    router.note(f"📚 Initiating learning from user feedback", tags=["learning"])

    # Launch parallel insight extraction (creates learning graph)
    behavior_task = router.app.call(
        "notification-intelligence.extract_behavior_pattern",
        user_id=user_id,
        notification_type=notification_type,
        response=user_response
    )

    channel_task = router.app.call(
        "notification-intelligence.extract_channel_insight",
        user_id=user_id,
        response=user_response
    )

    preference_task = router.app.call(
        "notification-intelligence.extract_preference_signal",
        notification_type=notification_type,
        response=user_response
    )

    # Gather all insights
    behavior, channel_insight, preference = await asyncio.gather(
        behavior_task, channel_task, preference_task
    )

    router.note("✅ All learning specialists complete", tags=["learning"])

    # Store in user memory
    user_mem = router.memory.actor(user_id)
    patterns = await user_mem.get("learned_patterns", default=[])
    channel_stats = await user_mem.get("channel_effectiveness", default={})

    # Add new insights
    new_insights = [behavior, channel_insight, preference]
    patterns.extend(new_insights)

    # Keep top 10 patterns by strength
    patterns = sorted(patterns, key=lambda x: x.get("strength", 0), reverse=True)[:10]

    # Update channel effectiveness
    if "action_taken" in user_response and user_response["action_taken"] == "opened":
        channel_used = user_response.get("channel_used", "email")
        current_score = channel_stats.get(channel_used, 0.5)
        # Moving average: 80% old + 20% new (opened = 1.0)
        channel_stats[channel_used] = current_score * 0.8 + 1.0 * 0.2

    # Save to memory
    await user_mem.set("learned_patterns", patterns)
    await user_mem.set("channel_effectiveness", channel_stats)

    # Increment sample size
    sample_size = await user_mem.get("sample_size", default=0)
    await user_mem.set("sample_size", sample_size + 1)

    router.note(f"💾 Stored {len(patterns)} patterns, sample size: {sample_size + 1}",
               tags=["learning", "storage"])

    return {
        "patterns_learned": len(patterns),
        "sample_size": sample_size + 1,
        "insights": new_insights
    }


@router.reasoner()
async def extract_behavior_pattern(
    user_id: str,
    notification_type: str,
    response: dict
) -> dict:
    """
    Learning specialist: Extracts user behavior patterns.

    Analyzes how user responded to notification to identify
    engagement patterns and attention preferences.
    """

    result = await router.ai(
        f"Notification: {notification_type}\nUser response: {response}\nBehavior pattern?",
        schema=BehaviorPattern
    )

    router.note(f"🔍 Behavior: {result.pattern}", tags=["learning", "behavior"])

    return result.model_dump()


@router.reasoner()
async def extract_channel_insight(
    user_id: str,
    response: dict
) -> dict:
    """
    Learning specialist: Extracts channel effectiveness signals.

    Analyzes response time and engagement to determine how
    effective the delivery channel was for this user.
    """

    result = await router.ai(
        f"User response: {response}\nChannel effectiveness insight?",
        schema=ChannelInsight
    )

    router.note(f"📱 Channel: {result.pattern}", tags=["learning", "channel"])

    return result.model_dump()


@router.reasoner()
async def extract_preference_signal(
    notification_type: str,
    response: dict
) -> dict:
    """
    Learning specialist: Extracts user preference signals.

    Infers implicit user preferences about notification importance
    and desired handling based on their response behavior.
    """

    result = await router.ai(
        f"Notification: {notification_type}\nResponse: {response}\nPreference signal?",
        schema=PreferenceSignal
    )

    router.note(f"⭐ Preference: {result.pattern}", tags=["learning", "preference"])

    return result.model_dump()
