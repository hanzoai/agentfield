/**
 * useGateway Hook
 *
 * React lifecycle hook for the gateway WebSocket connection.
 * Connects on mount, syncs agents, subscribes to events.
 * Passes auth token and tenant context for multi-tenant isolation.
 */

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { gateway } from '@/services/gatewayClient';
import { agentsList } from '@/services/gatewayApi';
import { useAgentStore } from '@/stores/agentStore';
import { useCanvasStore } from '@/stores/canvasStore';
import { useActionPillStore } from '@/stores/actionPillStore';
import { useAuth } from '@/contexts/AuthContext';
import type {
  ConnectParams,
  GatewayConnectionState,
  ChatEvent,
  AgentEvent,
  AgentSummary,
  ExecApprovalRequestEvent,
} from '@/types/gateway';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL as string || 'wss://bot.hanzo.ai';
const CLIENT_VERSION = '2.0.0';

/** Validate gateway URL against allowed protocols */
function validateGatewayUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (!['ws:', 'wss:'].includes(parsed.protocol)) {
      return 'wss://bot.hanzo.ai';
    }
    if (import.meta.env.PROD && parsed.protocol !== 'wss:') {
      return 'wss://bot.hanzo.ai';
    }
    return url;
  } catch {
    return 'wss://bot.hanzo.ai';
  }
}

const VALIDATED_URL = validateGatewayUrl(GATEWAY_URL);

// ---------------------------------------------------------------------------
// Tenant context from auth or URL
// ---------------------------------------------------------------------------

export interface TenantContext {
  orgId?: string;
  projectId?: string;
  tenantId?: string;
  actorId?: string;
  env?: string;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useGateway(tenant?: TenantContext) {
  const [connectionState, setConnectionState] = useState<GatewayConnectionState>('disconnected');
  const syncedRef = useRef(false);
  const { apiKey } = useAuth();

  // Unique client ID per session (not per page load)
  const clientId = useMemo(
    () => `playground-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    []
  );

  const setAgents = useAgentStore((s) => s.setAgents);
  const handleChatEvent = useAgentStore((s) => s.handleChatEvent);
  const handleAgentEvent = useAgentStore((s) => s.handleAgentEvent);
  const upsertBot = useCanvasStore((s) => s.upsertBot);
  const addApproval = useActionPillStore((s) => s.add);

  /** Build ConnectParams with auth + tenant context */
  const buildConnectParams = useCallback((): ConnectParams => ({
    minProtocol: 1,
    maxProtocol: 1,
    client: {
      id: clientId,
      version: CLIENT_VERSION,
      platform: 'web',
      mode: 'operator',
      displayName: 'Hanzo Playground',
    },
    role: 'operator',
    scopes: ['operator.admin'],
    ...(apiKey ? { auth: { token: apiKey } } : {}),
    ...(tenant ? {
      tenant: {
        orgId: tenant.orgId,
        projectId: tenant.projectId,
        tenantId: tenant.tenantId ?? tenant.orgId,
        actorId: tenant.actorId,
        env: tenant.env ?? (import.meta.env.PROD ? 'production' : 'development'),
      },
    } : {}),
  }), [clientId, apiKey, tenant]);

  // Sync agents from gateway to both stores
  const syncAgents = useCallback(async () => {
    try {
      const agents = await agentsList();
      setAgents(agents);

      for (const agent of agents) {
        upsertBot(agent.id, {
          name: agent.name,
          emoji: agent.emoji,
          avatar: agent.avatar,
          status: agent.status,
          sessionKey: agent.sessionKey,
          model: agent.model,
          workspace: agent.workspace,
          source: 'cloud',
        });
      }
    } catch {
      // Gateway not ready or auth failed — will retry on reconnect
    }
  }, [setAgents, upsertBot]);

  // Handle agents appearing from snapshot
  const syncFromSnapshot = useCallback((agents: AgentSummary[]) => {
    setAgents(agents);
    for (const agent of agents) {
      upsertBot(agent.id, {
        name: agent.name,
        emoji: agent.emoji,
        avatar: agent.avatar,
        status: agent.status,
        sessionKey: agent.sessionKey,
        model: agent.model,
        workspace: agent.workspace,
        source: 'cloud',
      });
    }
  }, [setAgents, upsertBot]);

  useEffect(() => {
    // Subscribe to connection state
    const unsubState = gateway.onStateChange((state) => {
      setConnectionState(state);

      // On connected, sync agents
      if (state === 'connected' && !syncedRef.current) {
        syncedRef.current = true;

        const snapshot = gateway.snapshot;
        if (snapshot?.agents && snapshot.agents.length > 0) {
          syncFromSnapshot(snapshot.agents);
        } else {
          syncAgents();
        }
      }

      if (state === 'disconnected' || state === 'error') {
        syncedRef.current = false;
      }
    });

    // Subscribe to real-time events
    const unsubChat = gateway.on('chat', (payload) => {
      handleChatEvent(payload as ChatEvent);
    });

    const unsubAgent = gateway.on('agent', (payload) => {
      handleAgentEvent(payload as AgentEvent);
    });

    const unsubApproval = gateway.on('exec.approval.requested', (payload) => {
      addApproval(payload as ExecApprovalRequestEvent);
    });

    // Connect to gateway with auth + tenant
    gateway.connect(VALIDATED_URL, buildConnectParams());

    return () => {
      unsubState();
      unsubChat();
      unsubAgent();
      unsubApproval();
      // Don't disconnect on unmount — singleton persists across routes
    };
  }, [syncAgents, syncFromSnapshot, handleChatEvent, handleAgentEvent, addApproval, buildConnectParams]);

  const reconnect = useCallback(() => {
    syncedRef.current = false;
    gateway.disconnect();
    gateway.connect(VALIDATED_URL, buildConnectParams());
  }, [buildConnectParams]);

  return {
    connectionState,
    isConnected: connectionState === 'connected',
    reconnect,
    syncAgents,
  };
}
