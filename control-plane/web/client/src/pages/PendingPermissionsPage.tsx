import { useCallback, useEffect, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Clock,
  CheckCircle,
  XCircle,
  Renew,
  Copy,
} from "@/components/ui/icon-bridge";
import { CompactTable } from "@/components/ui/CompactTable";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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
import * as permissionsApi from "../services/permissionsApi";
import type { PermissionApproval } from "../types/permissions";
import { formatRelativeTime } from "../utils/dateFormat";

const GRID_TEMPLATE = "60px minmax(150px,1.5fr) minmax(150px,1.5fr) minmax(180px,2fr) minmax(120px,1fr) 140px";

export function PendingPermissionsPage() {
  const [permissions, setPermissions] = useState<PermissionApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Sort state
  const [sortBy, setSortBy] = useState("created_at");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Dialog state
  const [approveDialog, setApproveDialog] = useState<PermissionApproval | null>(null);
  const [rejectDialog, setRejectDialog] = useState<PermissionApproval | null>(null);
  const [durationHours, setDurationHours] = useState<string>("720");
  const [rejectReason, setRejectReason] = useState<string>("");
  const [actionLoading, setActionLoading] = useState(false);

  const fetchPermissions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await permissionsApi.listPendingPermissions();
      setPermissions(response.permissions || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load permissions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPermissions();
  }, [fetchPermissions]);

  // Auto-dismiss success message
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(label);
      setTimeout(() => setCopiedText(null), 2000);
    } catch {
      // Clipboard API may not be available
    }
  };

  const handleApprove = async () => {
    if (!approveDialog) return;
    setActionLoading(true);
    try {
      const hours = parseInt(durationHours, 10);
      await permissionsApi.approvePermission(approveDialog.id, {
        duration_hours: isNaN(hours) ? undefined : hours,
      });
      setSuccess(`Permission approved for ${approveDialog.caller_agent_id} → ${approveDialog.target_agent_id}`);
      setApproveDialog(null);
      setDurationHours("720");
      fetchPermissions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve permission");
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    if (!rejectDialog) return;
    setActionLoading(true);
    try {
      await permissionsApi.rejectPermission(rejectDialog.id, {
        reason: rejectReason || undefined,
      });
      setSuccess(`Permission rejected for ${rejectDialog.caller_agent_id} → ${rejectDialog.target_agent_id}`);
      setRejectDialog(null);
      setRejectReason("");
      fetchPermissions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reject permission");
    } finally {
      setActionLoading(false);
    }
  };

  const handleSortChange = (field: string) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  const columns = [
    {
      key: "status",
      header: "Status",
      sortable: false,
      align: "center" as const,
      render: () => (
        <Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-500/30">
          <Clock className="h-3 w-3 mr-1" />
          Pending
        </Badge>
      ),
    },
    {
      key: "caller",
      header: "Caller Agent",
      sortable: false,
      align: "left" as const,
      render: (item: PermissionApproval) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center gap-1">
                <span className="font-mono text-sm truncate">{item.caller_agent_id}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-5 w-5 opacity-50 hover:opacity-100"
                  onClick={(e: React.MouseEvent) => {
                    e.stopPropagation();
                    handleCopy(item.caller_did, "Caller DID");
                  }}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p className="font-mono text-xs">{item.caller_did}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
    },
    {
      key: "target",
      header: "Target Agent",
      sortable: false,
      align: "left" as const,
      render: (item: PermissionApproval) => (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center gap-1">
                <span className="font-mono text-sm truncate">{item.target_agent_id}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-5 w-5 opacity-50 hover:opacity-100"
                  onClick={(e: React.MouseEvent) => {
                    e.stopPropagation();
                    handleCopy(item.target_did, "Target DID");
                  }}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p className="font-mono text-xs">{item.target_did}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ),
    },
    {
      key: "reason",
      header: "Reason",
      sortable: false,
      align: "left" as const,
      render: (item: PermissionApproval) => (
        <span className="text-sm text-muted-foreground truncate">
          {item.reason || "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Requested",
      sortable: true,
      align: "left" as const,
      render: (item: PermissionApproval) => (
        <span className="text-sm text-muted-foreground" title={new Date(item.created_at).toLocaleString()}>
          {formatRelativeTime(item.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      sortable: false,
      align: "center" as const,
      render: (item: PermissionApproval) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-green-600 hover:text-green-700 hover:bg-green-500/10"
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              setApproveDialog(item);
            }}
          >
            <CheckCircle className="h-4 w-4 mr-1" />
            Approve
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-red-600 hover:text-red-700 hover:bg-red-500/10"
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              setRejectDialog(item);
            }}
          >
            <XCircle className="h-4 w-4 mr-1" />
            Reject
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Pending Permissions</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Review and approve agent permission requests
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchPermissions}
          disabled={loading}
        >
          <Renew className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Success message */}
      {success && (
        <Alert className="bg-green-500/10 border-green-500/30">
          <CheckCircle className="h-4 w-4 text-green-600" />
          <AlertTitle className="text-green-600">Success</AlertTitle>
          <AlertDescription className="text-green-600">{success}</AlertDescription>
        </Alert>
      )}

      {/* Error message */}
      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Copy feedback */}
      {copiedText && (
        <div className="fixed bottom-4 right-4 bg-card border rounded-lg px-4 py-2 shadow-lg">
          <span className="text-sm">{copiedText} copied to clipboard</span>
        </div>
      )}

      {/* Table */}
      <div className="flex-1 min-h-0">
        <CompactTable
          data={permissions}
          columns={columns}
          loading={loading}
          hasMore={false}
          isFetchingMore={false}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={handleSortChange}
          gridTemplate={GRID_TEMPLATE}
          getRowKey={(item) => String(item.id)}
          emptyState={{
            title: "No pending permissions",
            description: "There are no permission requests awaiting approval.",
          }}
        />
      </div>

      {/* Approve Dialog */}
      <Dialog open={!!approveDialog} onOpenChange={() => setApproveDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Approve Permission</DialogTitle>
            <DialogDescription>
              Allow <span className="font-mono">{approveDialog?.caller_agent_id}</span> to call{" "}
              <span className="font-mono">{approveDialog?.target_agent_id}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="duration">Duration (hours)</Label>
              <Input
                id="duration"
                type="number"
                value={durationHours}
                onChange={(e) => setDurationHours(e.target.value)}
                placeholder="720 (30 days)"
              />
              <p className="text-xs text-muted-foreground">
                Leave empty for no expiration. Default is 720 hours (30 days).
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApproveDialog(null)}>
              Cancel
            </Button>
            <Button onClick={handleApprove} disabled={actionLoading}>
              {actionLoading ? "Approving..." : "Approve"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject Dialog */}
      <Dialog open={!!rejectDialog} onOpenChange={() => setRejectDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Permission</DialogTitle>
            <DialogDescription>
              Deny <span className="font-mono">{rejectDialog?.caller_agent_id}</span> access to{" "}
              <span className="font-mono">{rejectDialog?.target_agent_id}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="reason">Reason (optional)</Label>
              <Input
                id="reason"
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                placeholder="Explain why this permission was rejected..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectDialog(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleReject} disabled={actionLoading}>
              {actionLoading ? "Rejecting..." : "Reject"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
