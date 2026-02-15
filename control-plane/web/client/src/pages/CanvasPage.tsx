/**
 * CanvasPage (Playground)
 *
 * Full-bleed infinite canvas for bot orchestration.
 * Responsive: sidebar panel on desktop, drawer on mobile.
 */

import { useEffect, useState } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { CanvasFlow } from '@/components/canvas/CanvasFlow';
import { CanvasSidebar } from '@/components/canvas/CanvasSidebar';
import { ConnectionIndicator } from '@/components/canvas/ConnectionIndicator';
import { ActionPill } from '@/components/canvas/ActionPill/ActionPill';
import { CommandPalette } from '@/components/canvas/CommandPalette';
import { useGateway } from '@/hooks/useGateway';
import { useCanvasStore } from '@/stores/canvasStore';
import { useAgentStore } from '@/stores/agentStore';

export function CanvasPage() {
  const { connectionState, isConnected, reconnect } = useGateway();
  const restore = useCanvasStore((s) => s.restore);
  const addStarter = useCanvasStore((s) => s.addStarter);
  const nodes = useCanvasStore((s) => s.nodes);
  const initialized = useAgentStore((s) => s.initialized);
  const agentCount = useAgentStore((s) => s.agents.size);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Restore persisted canvas on mount
  useEffect(() => { restore(); }, [restore]);

  // Add starter if canvas empty after initial sync
  useEffect(() => {
    if (initialized && nodes.length === 0) addStarter();
  }, [initialized, nodes.length, addStarter]);

  return (
    <ReactFlowProvider>
      <div className="relative flex h-full w-full overflow-hidden">
        {/* Sidebar */}
        <CanvasSidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        {/* Canvas area */}
        <div className="relative flex-1 min-w-0">
          <CanvasFlow />

          {/* Top bar */}
          <div className="absolute top-3 left-3 right-3 z-20 flex items-center justify-between pointer-events-none">
            {/* Left: sidebar toggle */}
            <button
              type="button"
              onClick={() => setSidebarOpen((prev) => !prev)}
              className="pointer-events-auto flex h-8 w-8 items-center justify-center rounded-lg border border-border/50 bg-card/90 text-muted-foreground shadow-sm backdrop-blur-sm transition-colors hover:bg-accent hover:text-foreground touch-manipulation"
              title="Toggle sidebar"
            >
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M2 4h10M2 7h10M2 10h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </button>

            {/* Right: connection + count */}
            <div className="pointer-events-auto flex items-center gap-2">
              {isConnected && agentCount > 0 && (
                <div className="flex items-center gap-1.5 rounded-full border border-border/50 bg-card/90 px-3 py-1.5 text-xs text-muted-foreground backdrop-blur-sm shadow-sm select-none">
                  <span className="font-medium text-foreground">{agentCount}</span>
                  <span>{agentCount === 1 ? 'bot' : 'bots'}</span>
                </div>
              )}
              <ConnectionIndicator state={connectionState} onReconnect={reconnect} />
            </div>
          </div>

          {/* ActionPill */}
          <ActionPill />

          {/* Empty state */}
          {!isConnected && connectionState !== 'connecting' && connectionState !== 'authenticating' && connectionState !== 'reconnecting' && (
            <div className="absolute inset-0 z-10 flex items-center justify-center pointer-events-none">
              <div className="flex flex-col items-center gap-3 text-center pointer-events-auto px-4">
                <div className="text-4xl">🤖</div>
                <h2 className="text-lg font-semibold">Hanzo Playground</h2>
                <p className="text-sm text-muted-foreground max-w-xs">
                  Connect to the gateway to see your bots. Click the indicator to reconnect.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* CommandPalette (Cmd+K) */}
      <CommandPalette />
    </ReactFlowProvider>
  );
}
