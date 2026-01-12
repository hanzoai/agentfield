'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000'

export interface AgentEvent {
  type: string
  execution_id?: string
  agent_name?: string
  event_type?: string
  message?: string
  tags?: string[]
  result?: Record<string, unknown>
  error?: string
  timestamp: string
  // learning_update payload
  response?: 'opened' | 'ignored' | 'dismissed'
  new_state?: {
    pattern_count?: number
    analysis_mode?: string
    specialists_used?: number
    open_rate?: number
  }
  scenario?: {
    id: string
    name: string
    notification_type: string
  }
  user?: {
    id: string
    analysis_mode: string
    specialists_used: number
  }
}

export interface UseAgentStreamReturn {
  connected: boolean
  events: AgentEvent[]
  currentExecution: string | null
  clearEvents: () => void
  clearTrace: () => void
}

export function useAgentStream(): UseAgentStreamReturn {
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [currentExecution, setCurrentExecution] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(`${WS_URL}/ws/events`)

    ws.onopen = () => {
      setConnected(true)
      console.log('WebSocket connected')
    }

    ws.onclose = () => {
      setConnected(false)
      console.log('WebSocket disconnected, reconnecting...')
      // Reconnect after 2 seconds
      reconnectTimeoutRef.current = setTimeout(connect, 2000)
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    ws.onmessage = (event) => {
      try {
        const data: AgentEvent = JSON.parse(event.data)

        // Track current execution
        if (data.type === 'execution_started' && data.execution_id) {
          setCurrentExecution(data.execution_id)
        } else if (data.type === 'execution_completed' || data.type === 'execution_failed') {
          // Don't clear execution - keep it for display
        }

        setEvents((prev) => [...prev, data])
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e)
      }
    }

    wsRef.current = ws
  }, [])

  const clearEvents = useCallback(() => {
    setEvents([])
    setCurrentExecution(null)
  }, [])

  const clearTrace = useCallback(() => {
    setEvents([])
  }, [])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      wsRef.current?.close()
    }
  }, [connect])

  // Send periodic pings to keep connection alive
  useEffect(() => {
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }))
      }
    }, 30000)

    return () => clearInterval(pingInterval)
  }, [])

  return { connected, events, currentExecution, clearEvents, clearTrace }
}
