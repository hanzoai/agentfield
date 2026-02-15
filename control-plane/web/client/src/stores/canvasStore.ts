/**
 * Canvas Store (Zustand)
 *
 * Manages ReactFlow nodes/edges/viewport.
 * Persists to localStorage across sessions.
 */

import { create } from 'zustand';
import type { Node, Edge, Viewport, XYPosition } from '@xyflow/react';
import type { Bot, BotView } from '@/types/canvas';
import { NODE_TYPES } from '@/types/canvas';

const STORAGE_KEY_PREFIX = 'playground';
const DEFAULT_VIEWPORT: Viewport = { x: 0, y: 0, zoom: 0.8 };

/** Tenant-scoped storage key to prevent cross-tenant data leaks */
function storageKey(tenantId?: string): string {
  return tenantId ? `${STORAGE_KEY_PREFIX}:${tenantId}` : STORAGE_KEY_PREFIX;
}

function id(): string {
  return `n_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface CanvasStore {
  nodes: Node[];
  edges: Edge[];
  viewport: Viewport;
  selectedNodeId: string | null;

  setNodes: (nodes: Node[]) => void;
  setEdges: (edges: Edge[]) => void;
  setViewport: (viewport: Viewport) => void;
  selectNode: (id: string | null) => void;

  upsertBot: (agentId: string, data: Partial<Bot>, position?: XYPosition) => void;
  removeBot: (agentId: string) => void;
  setBotView: (agentId: string, view: BotView) => void;
  setBotStatus: (agentId: string, status: Bot['status']) => void;

  addStarter: (position?: XYPosition) => void;

  persist: (tenantId?: string) => void;
  restore: (tenantId?: string) => void;
  /** Reset all state (call on logout/tenant switch) */
  reset: () => void;
}

export const useCanvasStore = create<CanvasStore>((set, get) => ({
  nodes: [],
  edges: [],
  viewport: DEFAULT_VIEWPORT,
  selectedNodeId: null,

  setNodes: (nodes) => set({ nodes }),
  setEdges: (edges) => set({ edges }),
  setViewport: (viewport) => set({ viewport }),
  selectNode: (nodeId) => set({ selectedNodeId: nodeId }),

  upsertBot: (agentId, data, position) => {
    const { nodes } = get();
    const existing = nodes.find(
      (n) => n.type === NODE_TYPES.bot && (n.data as unknown as Bot).agentId === agentId
    );

    if (existing) {
      set({
        nodes: nodes.map((n) =>
          n.id === existing.id
            ? { ...n, data: { ...n.data, ...data } }
            : n
        ),
      });
    } else {
      set({
        nodes: [...nodes, {
          id: id(),
          type: NODE_TYPES.bot,
          position: position ?? { x: Math.random() * 600, y: Math.random() * 400 },
          data: {
            agentId,
            name: data.name ?? 'Bot',
            status: data.status ?? 'idle',
            activeView: 'overview' as BotView,
            source: data.source ?? 'cloud',
            ...data,
          },
        }],
      });
    }
  },

  removeBot: (agentId) => {
    const { nodes, edges, selectedNodeId } = get();
    const node = nodes.find(
      (n) => n.type === NODE_TYPES.bot && (n.data as unknown as Bot).agentId === agentId
    );
    if (!node) return;
    set({
      nodes: nodes.filter((n) => n.id !== node.id),
      edges: edges.filter((e) => e.source !== node.id && e.target !== node.id),
      selectedNodeId: selectedNodeId === node.id ? null : selectedNodeId,
    });
  },

  setBotView: (agentId, view) => {
    const { nodes } = get();
    set({
      nodes: nodes.map((n) =>
        n.type === NODE_TYPES.bot && (n.data as unknown as Bot).agentId === agentId
          ? { ...n, data: { ...n.data, activeView: view } }
          : n
      ),
    });
  },

  setBotStatus: (agentId, status) => {
    const { nodes } = get();
    set({
      nodes: nodes.map((n) =>
        n.type === NODE_TYPES.bot && (n.data as unknown as Bot).agentId === agentId
          ? { ...n, data: { ...n.data, status } }
          : n
      ),
    });
  },

  addStarter: (position) => {
    const { nodes } = get();
    if (nodes.some((n) => n.type === NODE_TYPES.starter)) return;
    set({
      nodes: [...nodes, {
        id: id(),
        type: NODE_TYPES.starter,
        position: position ?? { x: 300, y: 300 },
        data: { placeholder: 'Add a bot...' },
      }],
    });
  },

  persist: (tenantId) => {
    const { nodes, edges, viewport } = get();
    try {
      localStorage.setItem(storageKey(tenantId), JSON.stringify({ nodes, edges, viewport }));
    } catch { /* storage full */ }
  },

  restore: (tenantId) => {
    try {
      const raw = localStorage.getItem(storageKey(tenantId));
      if (!raw) return;
      const { nodes, edges, viewport } = JSON.parse(raw);
      set({
        nodes: nodes ?? [],
        edges: edges ?? [],
        viewport: viewport ?? DEFAULT_VIEWPORT,
      });
    } catch { /* corrupt data */ }
  },

  reset: () => set({
    nodes: [],
    edges: [],
    viewport: DEFAULT_VIEWPORT,
    selectedNodeId: null,
  }),
}));
