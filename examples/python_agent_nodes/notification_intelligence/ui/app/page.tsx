'use client'

import { useCallback, useEffect, useState, useRef } from 'react'
import { useAgentStream } from '@/hooks/useAgentStream'
import { DashboardShell, DashboardHeader, DashboardMain } from '@/components/DashboardShell'
import { InputPanel, CustomFormData } from '@/components/InputPanel'
import { DecisionGraph } from '@/components/DecisionGraph'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

interface Scenario {
  id: string
  name: string
  description: string
}

interface Decision {
  deliver: string
  channel: string
  priority: number
  reasoning: string
}

interface ParsedInsight {
  raw: string
  value?: string
  score?: number
  secondary?: string
  reasoning?: string
}

interface SpecialistData {
  emoji: string
  label: string
  color: string
  insight: ParsedInsight | null
  thinkingState: 'idle' | 'thinking' | 'revealed'
  thinkingStartTime?: number
}

type Phase = 'idle' | 'routing' | 'specialists' | 'synthesis' | 'complete'
type ScenarioMode = 'predefined' | 'custom'

const SPECIALISTS: Record<string, { emoji: string; color: string; label: string }> = {
  urgency: { emoji: '⚡', color: 'amber', label: 'Urgency' },
  channel: { emoji: '📱', color: 'blue', label: 'Channel' },
  user_state: { emoji: '👤', color: 'purple', label: 'User State' },
  timing: { emoji: '⏰', color: 'green', label: 'Timing' },
  context: { emoji: '🔍', color: 'cyan', label: 'Context' },
}

function parseInsight(agentName: string, message: string): ParsedInsight {
  const raw = message

  let cleaned = message
  for (const spec of Object.values(SPECIALISTS)) {
    if (message.startsWith(spec.emoji)) {
      cleaned = message.slice(spec.emoji.length).trim()
      break
    }
  }

  const [mainPart, reasoningPart] = cleaned.split(' | ')
  const reasoning = reasoningPart?.trim()

  if (agentName === 'urgency') {
    const match = mainPart.match(/Urgency:\s*(\d+)\/100\s*\(([^)]+)\)/)
    if (match) {
      return { raw, score: parseInt(match[1]), value: match[2], secondary: `${match[1]}/100`, reasoning }
    }
  }

  if (agentName === 'channel') {
    const match = mainPart.match(/Channel:\s*(\w+)\s*\(confidence:\s*([\d.]+)(?:,\s*backup:\s*(\w+))?\)/)
    if (match) {
      const backup = match[3] ? ` (backup: ${match[3]})` : ''
      return {
        raw,
        value: match[1],
        score: Math.round(parseFloat(match[2]) * 100),
        secondary: `${Math.round(parseFloat(match[2]) * 100)}% confidence${backup}`,
        reasoning,
      }
    }
  }

  if (agentName === 'user_state') {
    const match = mainPart.match(/User:\s*([^,]+),\s*engagement\s*([\d.]+)%/)
    if (match) {
      return { raw, value: match[1], score: parseFloat(match[2]), secondary: `${match[2]}% engagement`, reasoning }
    }
  }

  if (agentName === 'timing') {
    const match = mainPart.match(/Timing:\s*(\w+)(?:\s*\(until\s*([^)]+)\))?/)
    if (match) {
      const delayInfo = match[2] ? `until ${match[2]}` : undefined
      return { raw, value: match[1], secondary: delayInfo, reasoning }
    }
  }

  if (agentName === 'context') {
    const match = mainPart.match(/Context:\s*(\w+)\s*priority\s*\((\d+)\/100\)/)
    if (match) {
      return { raw, value: match[1], score: parseInt(match[2]), secondary: `${match[2]}/100 priority`, reasoning }
    }
  }

  return { raw, value: cleaned, reasoning }
}

function deriveSpecialistInsights(decision: Decision): Record<string, ParsedInsight> {
  const priority = decision.priority
  const deliver = decision.deliver
  const channel = decision.channel
  const reasoning = decision.reasoning || ''

  const urgencyValue = priority >= 80 ? 'immediate' : priority >= 60 ? 'moderate' : 'flexible'
  const urgencyInsight: ParsedInsight = {
    raw: `Urgency: ${priority}/100 (${urgencyValue})`,
    value: urgencyValue,
    score: priority,
    secondary: `${priority}/100`,
    reasoning: priority >= 70 ? 'Time-sensitive action needed' : 'Can be delayed if needed',
  }

  const channelConfidence = priority >= 70 ? 0.85 : 0.7
  const channelInsight: ParsedInsight = {
    raw: `Channel: ${channel} (confidence: ${channelConfidence.toFixed(2)})`,
    value: channel,
    score: Math.round(channelConfidence * 100),
    secondary: `${Math.round(channelConfidence * 100)}% confidence`,
    reasoning: `Best channel for ${deliver === 'now' ? 'immediate' : 'scheduled'} delivery`,
  }

  const userActive = deliver === 'now' || deliver === 'delay'
  const engagement = deliver === 'skip' ? 30 : deliver === 'batch' ? 55 : deliver === 'delay' ? 65 : 75
  const userStateInsight: ParsedInsight = {
    raw: `User: ${userActive ? 'receptive' : 'fatigued'}, engagement ${engagement}%`,
    value: userActive ? 'receptive' : 'fatigued',
    score: engagement,
    secondary: `${engagement}% engagement`,
    reasoning: reasoning.toLowerCase().includes('fatigue')
      ? 'High notification fatigue detected'
      : reasoning.toLowerCase().includes('browsing')
        ? 'User currently active'
        : 'Normal engagement level',
  }

  const timingValue =
    deliver === 'now' ? 'now' : deliver === 'delay' ? 'delay' : deliver === 'batch' ? 'batch' : 'skip'
  const timingInsight: ParsedInsight = {
    raw: `Timing: ${timingValue}`,
    value: timingValue,
    secondary: deliver === 'delay' ? 'until optimal window' : undefined,
    reasoning:
      reasoning.toLowerCase().includes('hour') || reasoning.toLowerCase().includes('morning')
        ? 'Outside peak engagement hours'
        : reasoning.toLowerCase().includes('browsing')
          ? 'User currently browsing'
          : 'Optimal timing window',
  }

  const contextPriority = priority >= 80 ? 'high' : priority >= 50 ? 'medium' : 'low'
  const contextInsight: ParsedInsight = {
    raw: `Context: ${contextPriority} priority (${priority}/100)`,
    value: contextPriority,
    score: priority,
    secondary: `${priority}/100 priority`,
    reasoning: reasoning.slice(0, 60) + (reasoning.length > 60 ? '...' : ''),
  }

  return {
    urgency: urgencyInsight,
    channel: channelInsight,
    user_state: userStateInsight,
    timing: timingInsight,
    context: contextInsight,
  }
}

export default function Home() {
  const { connected, events, clearEvents } = useAgentStream()
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('')
  const [isRunning, setIsRunning] = useState(false)
  const [decision, setDecision] = useState<Decision | null>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [specialists, setSpecialists] = useState<Record<string, SpecialistData>>(() => {
    const initial: Record<string, SpecialistData> = {}
    for (const [key, config] of Object.entries(SPECIALISTS)) {
      initial[key] = { ...config, insight: null, thinkingState: 'idle' }
    }
    return initial
  })
  const [synthesisMessage, setSynthesisMessage] = useState<string | null>(null)
  const [routingInfo, setRoutingInfo] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [scenarioMode, setScenarioMode] = useState<ScenarioMode>('predefined')
  const [thinkingPhraseIndex, setThinkingPhraseIndex] = useState(0)
  const [customForm, setCustomForm] = useState<CustomFormData>({
    notification_type: 'abandoned_cart',
    cart_value: 150,
    items: 'Running Shoes, Sports Watch',
    abandoned_minutes: 30,
    user_tier: 'standard',
    previous_purchases: 2,
    notifications_today: 1,
    user_currently_browsing: false,
    hour_in_user_timezone: 14,
    recent_notifications_ignored: 0,
    user_engagement_level: 'high',
  })

  // Cycle through thinking phrases
  useEffect(() => {
    if (!isRunning) return
    const interval = setInterval(() => {
      setThinkingPhraseIndex((i: number) => (i + 1) % 4)
    }, 800)
    return () => clearInterval(interval)
  }, [isRunning])

  // Load scenarios on mount
  useEffect(() => {
    fetch(`${API_URL}/scenarios`)
      .then((res) => res.json())
      .then((data) => {
        setScenarios(data.scenarios || [])
        if (data.scenarios?.length > 0) {
          setSelectedScenarioId(data.scenarios[0].id)
        }
      })
      .catch(console.error)
  }, [])

  // Track how many events we've processed to avoid reprocessing
  const processedEventsCountRef = useRef<number>(0)
  // Flag to prevent reprocessing old events during reset
  const isResettingRef = useRef<boolean>(false)

  // Process events - simple immediate updates
  useEffect(() => {
    // Skip processing if we're in the middle of a reset
    if (isResettingRef.current) {
      // Reset complete when events are cleared
      if (events.length === 0) {
        isResettingRef.current = false
        processedEventsCountRef.current = 0
      }
      return
    }

    const newEvents = events.slice(processedEventsCountRef.current)
    if (newEvents.length === 0) return
    processedEventsCountRef.current = events.length

    for (const event of newEvents) {
      if (event.type === 'execution_started') {
        if (phase === 'idle') {
          setPhase('specialists')
        }
      }

      if (event.type === 'agent_event') {
        const msg = event.message || ''
        let agentName = event.agent_name || ''
        const tags = event.tags || []

        if (!agentName || agentName === 'system') {
          if (tags.includes('specialist')) {
            if (tags.includes('urgency') || msg.startsWith('⚡')) agentName = 'urgency'
            else if (tags.includes('channel') || msg.startsWith('📱')) agentName = 'channel'
            else if (tags.includes('user-state') || msg.startsWith('👤')) agentName = 'user_state'
            else if (tags.includes('timing') || msg.startsWith('⏰')) agentName = 'timing'
            else if (tags.includes('context') || msg.startsWith('🔍')) agentName = 'context'
          } else if (tags.includes('synthesis')) {
            agentName = 'synthesis'
          }
        }

        if (agentName in SPECIALISTS) {
          const parsed = parseInsight(agentName, msg)
          setSpecialists((prev: Record<string, SpecialistData>) => ({
            ...prev,
            [agentName]: {
              ...prev[agentName],
              insight: parsed,
              thinkingState: 'revealed',
            },
          }))
        }

        if (agentName === 'synthesis') {
          setPhase('synthesis')
          if (msg.includes('Final:') || msg.includes('Decision:')) {
            setSynthesisMessage(msg)
          }
        }
      }

      if (event.type === 'execution_completed' && event.result) {
        setIsRunning(false)
        setPhase('complete')
        const result = event.result.decision || event.result
        const dec = result as Decision
        setDecision(dec)
        setError(null)

        setSpecialists((prev: Record<string, SpecialistData>) => {
          const hasAnyInsight = Object.values(prev).some((s) => s.insight !== null)
          if (!hasAnyInsight) {
            const derived = deriveSpecialistInsights(dec)
            const updated = { ...prev }
            Object.keys(updated).forEach((key) => {
              if (derived[key]) {
                updated[key] = {
                  ...updated[key],
                  insight: derived[key],
                  thinkingState: 'revealed',
                }
              }
            })
            return updated
          }
          return prev
        })
      }

      if (event.type === 'execution_failed') {
        setIsRunning(false)
        setPhase('idle')
        setError(event.error || 'Unknown error')
      }
    }
  }, [events, phase])

  const handleRun = useCallback(async () => {
    if (!selectedScenarioId) return

    // Block event processing during reset to prevent reprocessing old events
    isResettingRef.current = true

    // Reset all state BEFORE setting isRunning to prevent flash of old data with new running state
    const reset: Record<string, SpecialistData> = {}
    for (const [key, config] of Object.entries(SPECIALISTS)) {
      reset[key] = { ...config, insight: null, thinkingState: 'idle' }
    }
    setSpecialists(reset)
    setDecision(null)
    setPhase('idle')
    setSynthesisMessage(null)
    setRoutingInfo(null)
    setError(null)
    setThinkingPhraseIndex(0)
    clearEvents()

    // Set running state AFTER all data is reset
    setIsRunning(true)

    try {
      await fetch(`${API_URL}/trigger`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: selectedScenarioId,
          user_id: 'user_new_001',
        }),
      })
    } catch (err) {
      setIsRunning(false)
      setError(err instanceof Error ? err.message : 'Failed to trigger')
    }
  }, [selectedScenarioId, clearEvents])

  const handleCustomRun = useCallback(async () => {
    // Block event processing during reset to prevent reprocessing old events
    isResettingRef.current = true

    // Reset all state BEFORE setting isRunning to prevent flash of old data with new running state
    const reset: Record<string, SpecialistData> = {}
    for (const [key, config] of Object.entries(SPECIALISTS)) {
      reset[key] = { ...config, insight: null, thinkingState: 'idle' }
    }
    setSpecialists(reset)
    setDecision(null)
    setPhase('idle')
    setSynthesisMessage(null)
    setRoutingInfo(null)
    setError(null)
    setThinkingPhraseIndex(0)
    clearEvents()

    // Set running state AFTER all data is reset
    setIsRunning(true)

    let notification_data: Record<string, unknown> = {}
    const { notification_type } = customForm

    if (notification_type === 'abandoned_cart') {
      notification_data = {
        cart_value: customForm.cart_value || 100,
        items: (customForm.items || '').split(',').map((s: string) => s.trim()).filter(Boolean),
        abandoned_minutes_ago: customForm.abandoned_minutes || 30,
        cart_id: `cart_${Date.now()}`,
      }
    } else if (notification_type === 'flash_sale') {
      notification_data = {
        discount_percent: customForm.discount_percent || 30,
        expires_in_hours: customForm.expires_hours || 4,
        category: customForm.category || 'General',
        featured_items: (customForm.items || '').split(',').map((s: string) => s.trim()).filter(Boolean),
      }
    } else if (notification_type === 'back_in_stock') {
      notification_data = {
        item_name: customForm.item_name || 'Product',
        item_price: customForm.item_price || 99.99,
        stock_quantity: customForm.stock_quantity || 10,
        wishlisted_days_ago: 7,
      }
    } else if (notification_type === 'price_drop') {
      notification_data = {
        item_name: customForm.item_name || 'Product',
        original_price: customForm.original_price || 199.99,
        new_price: customForm.new_price || 149.99,
        discount_percent:
          customForm.original_price && customForm.new_price
            ? Math.round((1 - customForm.new_price / customForm.original_price) * 100)
            : 25,
        price_valid_until: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      }
    } else if (notification_type === 'shipping_update') {
      notification_data = {
        order_id: customForm.order_id || `ORD-${Date.now()}`,
        status: customForm.delivery_status || 'out_for_delivery',
        estimated_delivery: customForm.estimated_delivery || 'Today by 6 PM',
        carrier: 'UPS',
        items_count: 1,
      }
    }

    const context: Record<string, unknown> = {
      user_tier: customForm.user_tier || 'standard',
      previous_purchases: customForm.previous_purchases || 0,
      notifications_sent_today: customForm.notifications_today || 0,
      user_currently_browsing: customForm.user_currently_browsing || false,
      current_hour_user_timezone: customForm.hour_in_user_timezone ?? 14,
      recent_notifications_ignored: customForm.recent_notifications_ignored || 0,
      user_engagement_level: customForm.user_engagement_level || 'high',
    }

    try {
      await fetch(`${API_URL}/trigger-custom`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notification_type,
          notification_data,
          context,
          user_id: 'user_new_001',
        }),
      })
    } catch (err) {
      setIsRunning(false)
      setError(err instanceof Error ? err.message : 'Failed to trigger custom scenario')
    }
  }, [customForm, clearEvents])

  return (
    <DashboardShell>
      <DashboardHeader>
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center shadow-sm">
            <span className="text-sm">🔔</span>
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight">Notification Intelligence</h1>
            <p className="text-[10px] text-zinc-500">Watch AI agents analyze and decide on notification delivery</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}
          />
          <span className="text-zinc-600">{connected ? 'Live' : 'Offline'}</span>
        </div>
      </DashboardHeader>

      <DashboardMain className="flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-zinc-800">
        <InputPanel
          scenarios={scenarios}
          selectedScenarioId={selectedScenarioId}
          setSelectedScenarioId={setSelectedScenarioId}
          scenarioMode={scenarioMode}
          setScenarioMode={setScenarioMode}
          customForm={customForm}
          setCustomForm={setCustomForm}
          isRunning={isRunning}
          onRunPredefined={handleRun}
          onRunCustom={handleCustomRun}
          className="w-full md:w-[420px] lg:w-[480px] shrink-0 h-full overflow-hidden"
        />
        <DecisionGraph
          specialists={specialists}
          phase={phase}
          decision={decision}
          isRunning={isRunning}
          synthesisMessage={synthesisMessage}
          thinkingPhraseIndex={thinkingPhraseIndex}
          error={error}
          routingInfo={routingInfo}
          className="flex-1 min-w-0 h-full overflow-hidden bg-zinc-950"
        />
      </DashboardMain>
    </DashboardShell>
  )
}
