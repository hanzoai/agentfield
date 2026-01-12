'use client'

import React from 'react'

function cn(...classes: (string | undefined | false)[]) {
  return classes.filter(Boolean).join(' ')
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

interface Decision {
  deliver: string
  channel: string
  priority: number
  reasoning: string
}

type Phase = 'idle' | 'routing' | 'specialists' | 'synthesis' | 'complete'

const GRAPH_ANALYST_KEYS = ['urgency', 'channel', 'user_state', 'timing'] as const
type GraphAnalystKey = (typeof GRAPH_ANALYST_KEYS)[number]

const ANALYST_POSITIONS: Record<GraphAnalystKey, { left: string; top: string }> = {
  urgency: { left: '14%', top: '2%' },
  user_state: { left: '38%', top: '2%' },
  channel: { left: '62%', top: '2%' },
  timing: { left: '86%', top: '2%' },
}

const ANALYST_LINE_COLORS: Record<GraphAnalystKey, string> = {
  urgency: '#f59e0b',
  channel: '#60a5fa',
  user_state: '#a855f7',
  timing: '#22c55e',
}

const ACTION_NODES = [
  { key: 'now', label: 'Send Now', subtitle: 'Immediate delivery', icon: '📣' },
  { key: 'delay', label: 'Delay / Batch', subtitle: 'Wait for the best window', icon: '⏳' },
  { key: 'skip', label: 'Skip', subtitle: 'Suppress the notification', icon: '🛑' },
] as const

type ActionKey = (typeof ACTION_NODES)[number]['key']

const ACTION_POSITIONS: Record<ActionKey, { left: string; top: string }> = {
  now: { left: '20%', top: '58%' },
  delay: { left: '50%', top: '58%' },
  skip: { left: '80%', top: '58%' },
}

const ACTION_STYLES: Record<ActionKey, { border: string; bg: string; text: string; line: string }> = {
  now: { border: 'border-emerald-400/50', bg: 'bg-emerald-500/10', text: 'text-emerald-200', line: '#34d399' },
  delay: { border: 'border-amber-400/50', bg: 'bg-amber-500/10', text: 'text-amber-200', line: '#f59e0b' },
  skip: { border: 'border-rose-400/50', bg: 'bg-rose-500/10', text: 'text-rose-200', line: '#f87171' },
}

const ANALYST_LINE_POINTS: Record<GraphAnalystKey, { x: number; y: number }> = {
  urgency: { x: 140, y: 75 },
  user_state: { x: 380, y: 75 },
  channel: { x: 620, y: 75 },
  timing: { x: 860, y: 75 },
}

const ACTION_LINE_POINTS: Record<ActionKey, { x: number; y: number }> = {
  now: { x: 200, y: 540 },
  delay: { x: 500, y: 540 },
  skip: { x: 800, y: 540 },
}

const CONSENSUS_POINT = { x: 500, y: 310 }
const OUTCOME_POINT = { x: 500, y: 740 }

function buildBezierPath(start: { x: number; y: number }, end: { x: number; y: number }) {
  const midY = (start.y + end.y) / 2
  return `M ${start.x} ${start.y} C ${start.x} ${midY}, ${end.x} ${midY}, ${end.x} ${end.y}`
}

const THINKING_PHRASES: Record<string, string[]> = {
  urgency: [
    'Evaluating time sensitivity...',
    'Analyzing priority signals...',
    'Checking expiration windows...',
    'Assessing action urgency...',
  ],
  channel: [
    'Matching delivery channels...',
    'Analyzing engagement history...',
    'Optimizing reach strategy...',
    'Selecting best medium...',
  ],
  user_state: [
    'Reading user patterns...',
    'Checking fatigue signals...',
    'Analyzing engagement level...',
    'Predicting receptiveness...',
  ],
  timing: [
    'Checking timezone context...',
    'Evaluating optimal windows...',
    'Analyzing user activity...',
    'Finding best moment...',
  ],
  context: [
    'Extracting value signals...',
    'Analyzing situational factors...',
    'Weighing priority indicators...',
    'Building context picture...',
  ],
}

const colorClasses: Record<string, { border: string; bg: string; text: string; bar: string }> = {
  amber: { border: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-400', bar: 'bg-amber-500' },
  blue: { border: 'border-blue-500/40', bg: 'bg-blue-500/10', text: 'text-blue-400', bar: 'bg-blue-500' },
  purple: { border: 'border-purple-500/40', bg: 'bg-purple-500/10', text: 'text-purple-400', bar: 'bg-purple-500' },
  green: { border: 'border-green-500/40', bg: 'bg-green-500/10', text: 'text-green-400', bar: 'bg-green-500' },
  cyan: { border: 'border-cyan-500/40', bg: 'bg-cyan-500/10', text: 'text-cyan-400', bar: 'bg-cyan-500' },
}

const channelConfig: Record<string, { icon: string; label: string }> = {
  push: { icon: '📱', label: 'Push' },
  email: { icon: '📧', label: 'Email' },
  sms: { icon: '💬', label: 'SMS' },
  app: { icon: '🔔', label: 'In-App' },
}

interface DecisionGraphProps {
  specialists: Record<string, SpecialistData>
  phase: Phase
  decision: Decision | null
  isRunning: boolean
  synthesisMessage: string | null
  thinkingPhraseIndex: number
  error: string | null
  routingInfo: string | null
  className?: string
}

export function DecisionGraph({
  specialists,
  phase,
  decision,
  isRunning,
  synthesisMessage,
  thinkingPhraseIndex,
  error,
  routingInfo,
  className,
}: DecisionGraphProps) {
  const analystProgress = GRAPH_ANALYST_KEYS.filter((key) => specialists[key]?.insight).length
  const contextInsight = specialists.context?.insight
  const channelLabel = decision ? channelConfig[decision.channel]?.label || decision.channel : null
  // Only show decision-related visuals if we have a valid, complete decision
  const hasValidDecision = decision && decision.deliver && decision.priority !== undefined && decision.channel
  const decisionAction = hasValidDecision
    ? decision.deliver === 'batch'
      ? 'delay'
      : decision.deliver
    : null
  const outcomeMessage = hasValidDecision
    ? decision.deliver === 'now'
      ? `Sent via ${channelLabel}`
      : decision.deliver === 'delay'
        ? 'Queued for an optimal window'
        : decision.deliver === 'batch'
          ? 'Added to the next batch digest'
          : 'Suppressed to avoid fatigue'
    : isRunning
      ? 'Awaiting final consensus'
      : 'Run a scenario to see the outcome'

  return (
    <div className={cn('flex flex-col h-full overflow-hidden', className)}>
      {/* Error Display */}
      {error && (
        <div className="mx-4 mt-4 bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-400 text-sm shrink-0">
          {error}
        </div>
      )}

      {/* Routing Info */}
      {routingInfo && (
        <div className="mx-4 mt-4 bg-indigo-500/10 border border-indigo-500/30 rounded-lg px-3 py-2 flex items-center gap-2 shrink-0">
          <span className="text-indigo-400">🎯</span>
          <span className="text-xs text-indigo-300">{routingInfo.replace(/^[🌟⚡🎯]\s*/, '')}</span>
        </div>
      )}

      {/* Graph Container */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="bg-zinc-950/40 border border-white/5 ring-1 ring-white/5 rounded-2xl p-4 md:p-5 relative overflow-hidden shadow-[0_24px_90px_rgba(0,0,0,0.55)]">
          <div className="absolute -top-24 -right-20 w-72 h-72 bg-gradient-to-br from-emerald-500/10 via-amber-500/10 to-sky-500/10 blur-3xl" />
          <div className="absolute -bottom-24 -left-16 w-72 h-72 bg-gradient-to-tr from-indigo-500/10 via-cyan-500/10 to-rose-500/10 blur-3xl" />
          <div className="relative">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-xs font-semibold text-zinc-300 uppercase tracking-widest">
                  Decision Graph
                </h2>
                <p className="text-[10px] text-zinc-500">
                  Four analysts converge, then route to send, delay, or skip.
                </p>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                <span className="px-2 py-0.5 rounded-full bg-zinc-800/80 border border-zinc-700">
                  {analystProgress}/4 analysts
                </span>
                <span className="text-zinc-600">
                  {isRunning ? 'Live analysis' : decision ? 'Decision locked' : 'Idle'}
                </span>
              </div>
            </div>

            {/* Desktop Graph */}
            <div className="relative hidden md:block h-[calc(100vh-260px)] min-h-[500px] rounded-2xl overflow-hidden isolate">
              <div className="absolute inset-0 graph-grid opacity-25" />
              <div className="absolute inset-0 graph-vignette opacity-80" />
              <svg
                className="absolute inset-0 z-0 w-full h-full pointer-events-none"
                viewBox="0 0 1000 850"
                preserveAspectRatio="none"
              >
                <defs>
                  <marker
                    id="graph-arrow"
                    viewBox="0 0 10 10"
                    refX="8"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
                  </marker>
                  <filter id="edge-glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
                    <feMerge>
                      <feMergeNode in="coloredBlur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>
                {GRAPH_ANALYST_KEYS.map((key) => (
                  <path
                    key={`analyst-line-${key}`}
                    d={buildBezierPath(ANALYST_LINE_POINTS[key], CONSENSUS_POINT)}
                    stroke="currentColor"
                    style={{ color: ANALYST_LINE_COLORS[key] }}
                    className={cn(
                      'graph-edge',
                      specialists[key]?.insight
                        ? isRunning
                          ? 'graph-edge--active'
                          : 'graph-edge--solid'
                        : isRunning
                          ? 'graph-edge--running'
                          : 'graph-edge--idle'
                    )}
                    strokeWidth={specialists[key]?.insight ? 1.9 : 1.15}
                    markerEnd="url(#graph-arrow)"
                    filter={specialists[key]?.insight && isRunning ? 'url(#edge-glow)' : undefined}
                  />
                ))}
                {ACTION_NODES.map((action) => {
                  const isActive = decisionAction === action.key
                  const d = buildBezierPath(CONSENSUS_POINT, ACTION_LINE_POINTS[action.key])
                  return (
                    <g key={`action-line-${action.key}`}>
                      {isActive && (
                        <path
                          d={d}
                          stroke="currentColor"
                          style={{ color: ACTION_STYLES[action.key].line }}
                          className="graph-edge graph-edge--active-base"
                          strokeWidth={1.35}
                        />
                      )}
                      <path
                        d={d}
                        stroke="currentColor"
                        style={{ color: ACTION_STYLES[action.key].line }}
                        className={cn(
                          'graph-edge',
                          isActive
                            ? 'graph-edge--active'
                            : isRunning
                              ? 'graph-edge--running'
                              : 'graph-edge--idle'
                        )}
                        strokeWidth={isActive ? 2.25 : 1.1}
                        markerEnd="url(#graph-arrow)"
                        filter={isActive ? 'url(#edge-glow)' : undefined}
                      />
                    </g>
                  )
                })}
                {ACTION_NODES.map((action) => {
                  const isActive = decisionAction === action.key
                  const d = buildBezierPath(ACTION_LINE_POINTS[action.key], OUTCOME_POINT)
                  return (
                    <g key={`outcome-line-${action.key}`}>
                      {isActive && (
                        <path
                          d={d}
                          stroke="currentColor"
                          style={{ color: ACTION_STYLES[action.key].line }}
                          className="graph-edge graph-edge--active-base"
                          strokeWidth={1.35}
                        />
                      )}
                      <path
                        d={d}
                        stroke="currentColor"
                        style={{ color: ACTION_STYLES[action.key].line }}
                        className={cn(
                          'graph-edge',
                          isActive
                            ? 'graph-edge--active'
                            : isRunning
                              ? 'graph-edge--running'
                              : 'graph-edge--idle'
                        )}
                        strokeWidth={isActive ? 2.25 : 1.05}
                        markerEnd="url(#graph-arrow)"
                        filter={isActive ? 'url(#edge-glow)' : undefined}
                      />
                    </g>
                  )
                })}
              </svg>

              {/* Analyst Nodes */}
              {GRAPH_ANALYST_KEYS.map((key) => {
                const spec = specialists[key]
                if (!spec) return null
                const colors = colorClasses[spec.color]
                const hasInsight = Boolean(spec.insight)
                const scoreValue = spec.insight?.score ?? 0
                const thinkingPhrase = THINKING_PHRASES[key]?.[thinkingPhraseIndex] || 'Analyzing...'

                return (
                  <div
                    key={`analyst-${key}`}
                    className={cn(
                      'absolute z-20 -translate-x-1/2 w-28 h-[76px] rounded-xl border p-2 overflow-hidden backdrop-blur-md ring-1 ring-white/5 shadow-[0_12px_40px_rgba(0,0,0,0.55)] transition-all duration-300 transform-gpu',
                      hasInsight
                        ? `${colors.border} bg-zinc-950/80 translate-y-[-1px] scale-[1.01]`
                        : 'border-zinc-800/70 bg-zinc-950/70 scale-[0.99]'
                    )}
                    style={ANALYST_POSITIONS[key]}
                  >
                    {hasInsight && <div className={`absolute inset-0 ${colors.bg} opacity-60`} />}
                    <div className="relative flex flex-col items-center justify-center h-full text-center">
                      <div className="flex items-center gap-1">
                        <span className={`text-sm ${hasInsight ? '' : 'opacity-40 animate-pulse'}`}>
                          {spec.emoji}
                        </span>
                        <span
                          className={`text-[8px] uppercase tracking-wider ${hasInsight ? colors.text : 'text-zinc-500'}`}
                        >
                          {spec.label}
                        </span>
                      </div>
                      <div className="mt-1 w-full">
                        {hasInsight ? (
                          <>
                            <div className={`text-[11px] font-semibold ${colors.text} leading-tight`}>
                              {spec.insight?.value || 'N/A'}
                            </div>
                            {spec.insight?.score !== undefined && (
                              <div className="h-0.5 bg-zinc-800/80 rounded-full overflow-hidden mt-1">
                                <div
                                  className={`h-full ${colors.bar} transition-all duration-700 ease-out`}
                                  style={{ width: `${scoreValue}%` }}
                                />
                              </div>
                            )}
                          </>
                        ) : (
                          <div className="text-[9px] text-zinc-500 leading-tight">
                            {isRunning ? 'Analyzing...' : 'Waiting'}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}

              {/* Consensus Node */}
              <div
                className={cn(
                  'absolute z-20 -translate-x-1/2 w-36 h-[100px] rounded-xl border border-indigo-500/40 bg-zinc-950/80 p-2 overflow-hidden backdrop-blur-md ring-1 ring-white/5 shadow-[0_14px_45px_rgba(0,0,0,0.55)]',
                  isRunning && 'animate-graph-float'
                )}
                style={{ left: '50%', top: '32%' }}
              >
                <div className="absolute inset-0 bg-indigo-500/10 opacity-70" />
                <div className="relative flex flex-col items-center justify-center h-full text-center">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm">🧠</span>
                    <span className="text-[8px] uppercase tracking-wider text-indigo-300">Consensus</span>
                  </div>
                  <div className="mt-1 text-[9px] text-zinc-300/80 leading-snug">
                    {synthesisMessage
                      ? synthesisMessage.replace(/^[✨🧩]\s*/, '').slice(0, 60) + (synthesisMessage.length > 60 ? '...' : '')
                      : isRunning
                        ? 'Synthesizing insights...'
                        : 'Waiting for analysts'}
                  </div>
                  {decision && decision.priority !== undefined && channelLabel && (
                    <div className="mt-1.5 flex flex-wrap justify-center gap-1">
                      <span className="px-1.5 py-0.5 rounded-full bg-zinc-900/70 border border-white/5 text-[8px] text-zinc-200">
                        P{decision.priority}
                      </span>
                      <span className="px-1.5 py-0.5 rounded-full bg-zinc-900/70 border border-white/5 text-[8px] text-zinc-200">
                        {channelLabel}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Action Nodes */}
              {ACTION_NODES.map((action) => {
                const isActive = decisionAction === action.key
                const styles = ACTION_STYLES[action.key]
                return (
                  <div
                    key={`action-${action.key}`}
                    className={cn(
                      'absolute z-20 -translate-x-1/2 w-28 h-[72px] rounded-xl border p-2 overflow-hidden backdrop-blur-md ring-1 ring-white/5 shadow-[0_10px_35px_rgba(0,0,0,0.55)] transition-all duration-300 transform-gpu',
                      isActive
                        ? `${styles.border} bg-zinc-950/80 ${styles.text} shadow-[0_0_32px_rgba(255,255,255,0.06)] animate-pulse-glow translate-y-[-1px] scale-[1.01]`
                        : 'border-zinc-800/70 bg-zinc-950/70 text-zinc-400 hover:border-zinc-700/80 scale-[0.99]'
                    )}
                    style={ACTION_POSITIONS[action.key]}
                  >
                    <div className={`absolute inset-0 ${styles.bg} opacity-60`} />
                    <div className="relative flex flex-col items-center justify-center h-full text-center">
                      <div className="flex items-center gap-1.5">
                        <span className="text-base">{action.icon}</span>
                        {isActive && (
                          <span className={`text-[7px] uppercase tracking-wider ${styles.text}`}>
                            Active
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-[10px] font-semibold">{action.label}</div>
                      <div className="text-[8px] text-zinc-500 leading-tight">{action.subtitle}</div>
                    </div>
                  </div>
                )
              })}

              {/* Outcome Node */}
              <div
                className="absolute z-20 -translate-x-1/2 w-36 h-[88px] rounded-xl border border-zinc-800/80 bg-zinc-950/80 p-2 overflow-hidden backdrop-blur-md ring-1 ring-white/5 shadow-[0_12px_40px_rgba(0,0,0,0.55)]"
                style={{ left: '50%', top: '82%' }}
              >
                <div className="absolute inset-0 bg-white/[0.02]" />
                <div className="relative flex flex-col items-center justify-center h-full text-center">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm">🎯</span>
                    <span className="text-[8px] uppercase tracking-wider text-zinc-300">Outcome</span>
                  </div>
                  <div className="mt-1 text-[10px] text-zinc-200 leading-snug">{outcomeMessage}</div>
                  {hasValidDecision && decision.reasoning && (
                    <div className="mt-1 text-[8px] text-zinc-500 leading-tight">
                      {decision.reasoning.length > 50
                        ? `${decision.reasoning.slice(0, 50)}...`
                        : decision.reasoning}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Mobile Graph */}
            <div className="md:hidden space-y-3">
              <div className="grid grid-cols-2 gap-2">
                {GRAPH_ANALYST_KEYS.map((key) => {
                  const spec = specialists[key]
                  if (!spec) return null
                  const colors = colorClasses[spec.color]
                  const hasInsight = Boolean(spec.insight)
                  const thinkingPhrase = THINKING_PHRASES[key]?.[thinkingPhraseIndex] || 'Analyzing...'

                  return (
                    <div
                      key={`analyst-mobile-${key}`}
                      className={cn(
                        'border rounded-lg p-3',
                        hasInsight
                          ? `${colors.border} ${colors.bg}`
                          : 'border-zinc-800/70 bg-zinc-900/40'
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`text-base ${hasInsight ? '' : 'opacity-40'}`}>{spec.emoji}</span>
                        <span
                          className={`text-[10px] uppercase tracking-wider ${hasInsight ? colors.text : 'text-zinc-500'}`}
                        >
                          {spec.label}
                        </span>
                      </div>
                      <div className="mt-2 text-xs">
                        {hasInsight ? spec.insight?.value || 'N/A' : isRunning ? thinkingPhrase : 'Waiting'}
                      </div>
                      {spec.insight?.secondary && (
                        <div className="text-[10px] text-zinc-500 mt-1">{spec.insight.secondary}</div>
                      )}
                    </div>
                  )
                })}
              </div>

              <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/10 p-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🧠</span>
                  <span className="text-[10px] uppercase tracking-wider text-indigo-300">Consensus</span>
                </div>
                <div className="mt-2 text-[11px] text-zinc-400">
                  {synthesisMessage
                    ? synthesisMessage.replace(/^[✨🧩]\s*/, '')
                    : isRunning
                      ? 'Synthesizing analyst inputs.'
                      : 'Waiting for analysts.'}
                </div>
                {contextInsight?.value && (
                  <div className="mt-2 text-[10px] text-cyan-300/80">Context: {contextInsight.value}</div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-2">
                {ACTION_NODES.map((action) => {
                  const isActive = decisionAction === action.key
                  const styles = ACTION_STYLES[action.key]
                  return (
                    <div
                      key={`action-mobile-${action.key}`}
                      className={cn(
                        'rounded-lg border p-2 text-center',
                        isActive
                          ? `${styles.border} ${styles.bg} ${styles.text}`
                          : 'border-zinc-800/70 bg-zinc-900/30 text-zinc-500'
                      )}
                    >
                      <div className="text-sm">{action.icon}</div>
                      <div className="text-[10px] font-semibold mt-1">{action.label}</div>
                      {isActive && (
                        <div className="text-[9px] uppercase tracking-wider mt-1">Selected</div>
                      )}
                    </div>
                  )
                })}
              </div>

              <div className="rounded-xl border border-zinc-700 bg-zinc-900/60 p-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🎯</span>
                  <span className="text-[10px] uppercase tracking-wider text-zinc-300">Outcome</span>
                </div>
                <div className="mt-2 text-xs text-zinc-200">{outcomeMessage}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Empty State */}
        {phase === 'idle' && !decision && !error && (
          <div className="text-center py-8 text-zinc-600 text-sm">
            Select a scenario and click <span className="text-indigo-400">Analyze</span> to watch the agents
            work
          </div>
        )}
      </div>
    </div>
  )
}
