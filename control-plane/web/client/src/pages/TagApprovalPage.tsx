import { useCallback, useEffect, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  CheckCircle,
  XCircle,
  Renew,
} from "@/components/ui/icon-bridge";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import * as tagApprovalApi from "../services/tagApprovalApi";
import type { PendingAgentResponse } from "../services/tagApprovalApi";
import { AdminTokenPrompt } from "../components/AdminTokenPrompt";

export function TagApprovalPage() {
  const [agents, setAgents] = useState<PendingAgentResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Approve dialog
  const [approveAgent, setApproveAgent] = useState<PendingAgentResponse | null>(null);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [approveLoading, setApproveLoading] = useState(false);

  // Reject dialog
  const [rejectAgent, setRejectAgent] = useState<PendingAgentResponse | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [rejectLoading, setRejectLoading] = useState(false);

  const fetchAgents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await tagApprovalApi.listPendingAgents();
      setAgents(data.agents || []);
    } catch (err: any) {
      setError(err.message || "Failed to fetch pending agents");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
  }, [fetchAgents]);

  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  const openApproveDialog = (agent: PendingAgentResponse) => {
    setApproveAgent(agent);
    setSelectedTags([...(agent.proposed_tags || [])]);
  };

  const handleApprove = async () => {
    if (!approveAgent) return;
    try {
      setApproveLoading(true);
      await tagApprovalApi.approveAgentTags(approveAgent.agent_id, {
        approved_tags: selectedTags,
      });
      setSuccess(`Tags approved for agent ${approveAgent.agent_id}`);
      setApproveAgent(null);
      fetchAgents();
    } catch (err: any) {
      setError(err.message || "Failed to approve tags");
    } finally {
      setApproveLoading(false);
    }
  };

  const handleReject = async () => {
    if (!rejectAgent) return;
    try {
      setRejectLoading(true);
      await tagApprovalApi.rejectAgentTags(rejectAgent.agent_id, {
        reason: rejectReason || undefined,
      });
      setSuccess(`Tags rejected for agent ${rejectAgent.agent_id}`);
      setRejectAgent(null);
      setRejectReason("");
      fetchAgents();
    } catch (err: any) {
      setError(err.message || "Failed to reject tags");
    } finally {
      setRejectLoading(false);
    }
  };

  const toggleTag = (tag: string) => {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Tag Approvals</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Review and approve agent tag registrations
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchAgents} disabled={loading}>
          <Renew className="w-4 h-4 mr-1.5" />
          Refresh
        </Button>
      </div>

      {/* Alerts */}
      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {/* Admin token prompt — always visible when no token is set */}
      <AdminTokenPrompt onTokenSet={fetchAgents} />
      {success && (
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {/* Content */}
      {loading ? (
        <div className="text-center py-12 text-muted-foreground">Loading pending agents...</div>
      ) : agents.length === 0 ? (
        <div className="text-center py-12">
          <CheckCircle className="w-12 h-12 mx-auto text-muted-foreground/30 mb-3" />
          <h3 className="text-lg font-medium text-muted-foreground">No pending approvals</h3>
          <p className="text-sm text-muted-foreground/70 mt-1">
            All agents have been reviewed. New agents with manual-review tags will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map((agent) => (
            <div
              key={agent.agent_id}
              className="border rounded-lg p-4 flex items-start justify-between gap-4"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-mono text-sm font-medium truncate">
                    {agent.agent_id}
                  </span>
                  <Badge variant="outline" className="bg-amber-50 text-amber-700 border-amber-200">
                    pending
                  </Badge>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {(agent.proposed_tags || []).map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                  {(!agent.proposed_tags || agent.proposed_tags.length === 0) && (
                    <span className="text-xs text-muted-foreground">No tags proposed</span>
                  )}
                </div>
                <div className="text-xs text-muted-foreground mt-2">
                  Registered: {new Date(agent.registered_at).toLocaleString()}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-green-700 hover:text-green-800 hover:bg-green-50"
                  onClick={() => openApproveDialog(agent)}
                >
                  <CheckCircle className="w-3.5 h-3.5 mr-1" />
                  Approve
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-red-700 hover:text-red-800 hover:bg-red-50"
                  onClick={() => setRejectAgent(agent)}
                >
                  <XCircle className="w-3.5 h-3.5 mr-1" />
                  Reject
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Approve Dialog */}
      <Dialog open={!!approveAgent} onOpenChange={(open) => !open && setApproveAgent(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Approve Tags</DialogTitle>
            <DialogDescription>
              Select which tags to approve for agent{" "}
              <span className="font-mono font-medium">{approveAgent?.agent_id}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Label className="mb-3 block">Proposed Tags</Label>
            <div className="flex flex-wrap gap-2">
              {(approveAgent?.proposed_tags || []).map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => toggleTag(tag)}
                  className={`inline-flex items-center rounded-md px-2.5 py-1 text-xs font-medium border cursor-pointer transition-colors ${
                    selectedTags.includes(tag)
                      ? "bg-green-100 text-green-800 border-green-300"
                      : "bg-muted text-muted-foreground border-border opacity-50"
                  }`}
                >
                  {selectedTags.includes(tag) ? (
                    <CheckCircle className="w-3 h-3 mr-1" />
                  ) : null}
                  {tag}
                </button>
              ))}
            </div>
            {selectedTags.length === 0 && (
              <p className="text-sm text-amber-600 mt-2">
                Select at least one tag to approve.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApproveAgent(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleApprove}
              disabled={approveLoading || selectedTags.length === 0}
            >
              {approveLoading ? "Approving..." : `Approve ${selectedTags.length} tag(s)`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject Dialog */}
      <Dialog open={!!rejectAgent} onOpenChange={(open) => !open && setRejectAgent(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Tags</DialogTitle>
            <DialogDescription>
              Reject the proposed tags for agent{" "}
              <span className="font-mono font-medium">{rejectAgent?.agent_id}</span>.
              The agent will be set to offline status.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Label htmlFor="reject-reason">Reason (optional)</Label>
            <Input
              id="reject-reason"
              placeholder="Enter reason for rejection"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              className="mt-1.5"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectAgent(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleReject}
              disabled={rejectLoading}
            >
              {rejectLoading ? "Rejecting..." : "Reject Tags"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
