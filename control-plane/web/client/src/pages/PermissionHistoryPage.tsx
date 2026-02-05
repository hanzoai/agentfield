import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Clock,
  CheckCircle,
  XCircle,
  Renew,
  Copy,
  Trash,
} from "@/components/ui/icon-bridge";
import { CompactTable } from "@/components/ui/CompactTable";
import { SearchBar } from "@/components/ui/SearchBar";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import type { PermissionApproval, PermissionStatus } from "../types/permissions";
import { formatRelativeTime } from "../utils/dateFormat";

const GRID_TEMPLATE = "80px minmax(130px,1.2fr) minmax(130px,1.2fr) minmax(100px,1fr) minmax(120px,1fr) minmax(120px,1fr) 80px";

const STATUS_CONFIG: Record<PermissionStatus, { label: string; variant: string; icon: React.ReactNode }> = {
  pending: { label: "Pending", variant: "bg-amber-500/10 text-amber-600 border-amber-500/30", icon: <Clock className="h-3 w-3 mr-1" /> },
  approved: { label: "Approved", variant: "bg-green-500/10 text-green-600 border-green-500/30", icon: <CheckCircle className="h-3 w-3 mr-1" /> },
  rejected: { label: "Rejected", variant: "bg-red-500/10 text-red-600 border-red-500/30", icon: <XCircle className="h-3 w-3 mr-1" /> },
  revoked: { label: "Revoked", variant: "bg-red-500/10 text-red-600 border-red-500/30", icon: <Trash className="h-3 w-3 mr-1" /> },
  expired: { label: "Expired", variant: "bg-gray-500/10 text-gray-600 border-gray-500/30", icon: <Clock className="h-3 w-3 mr-1" /> },
};

export function PermissionHistoryPage() {
  const [permissions, setPermissions] = useState<PermissionApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Sort state
  const [sortBy, setSortBy] = useState("updated_at");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Revoke dialog
  const [revokeDialog, setRevokeDialog] = useState<PermissionApproval | null>(null);
  const [revokeReason, setRevokeReason] = useState<string>("");
  const [actionLoading, setActionLoading] = useState(false);

  // Debounce search
  useEffect(() => {
    const handle = window.setTimeout(() => {
      setDebouncedQuery(searchQuery.trim());
    }, 350);
    return () => window.clearTimeout(handle);
  }, [searchQuery]);

  const fetchPermissions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await permissionsApi.listAllPermissions();
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

  const handleRevoke = async () => {
    if (!revokeDialog) return;
    setActionLoading(true);
    try {
      await permissionsApi.revokePermission(revokeDialog.id, {
        reason: revokeReason || undefined,
      });
      setSuccess(`Permission revoked for ${revokeDialog.caller_agent_id} → ${revokeDialog.target_agent_id}`);
      setRevokeDialog(null);
      setRevokeReason("");
      fetchPermissions();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke permission");
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

  // Filter permissions
  const filteredPermissions = useMemo(() => {
    let result = permissions;

    // Status filter
    if (statusFilter !== "all") {
      result = result.filter((p) => p.status === statusFilter);
    }

    // Search filter
    if (debouncedQuery) {
      const query = debouncedQuery.toLowerCase();
      result = result.filter(
        (p) =>
          p.caller_agent_id.toLowerCase().includes(query) ||
          p.target_agent_id.toLowerCase().includes(query) ||
          p.caller_did.toLowerCase().includes(query) ||
          p.target_did.toLowerCase().includes(query)
      );
    }

    return result;
  }, [permissions, statusFilter, debouncedQuery]);

  const getActionDetails = (item: PermissionApproval) => {
    switch (item.status) {
      case "approved":
        return { by: item.approved_by, at: item.approved_at };
      case "rejected":
        return { by: item.rejected_by, at: item.rejected_at };
      case "revoked":
        return { by: item.revoked_by, at: item.revoked_at };
      default:
        return { by: null, at: null };
    }
  };

  const columns = [
    {
      key: "status",
      header: "Status",
      sortable: false,
      align: "center" as const,
      render: (item: PermissionApproval) => {
        const config = STATUS_CONFIG[item.status] || STATUS_CONFIG.pending;
        return (
          <Badge variant="outline" className={config.variant}>
            {config.icon}
            {config.label}
          </Badge>
        );
      },
    },
    {
      key: "caller",
      header: "Caller",
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
      header: "Target",
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
      key: "action_by",
      header: "Action By",
      sortable: false,
      align: "left" as const,
      render: (item: PermissionApproval) => {
        const { by } = getActionDetails(item);
        return <span className="text-sm text-muted-foreground">{by || "—"}</span>;
      },
    },
    {
      key: "action_at",
      header: "Action Date",
      sortable: true,
      align: "left" as const,
      render: (item: PermissionApproval) => {
        const { at } = getActionDetails(item);
        if (!at) return <span className="text-sm text-muted-foreground">—</span>;
        return (
          <span className="text-sm text-muted-foreground" title={new Date(at).toLocaleString()}>
            {formatRelativeTime(at)}
          </span>
        );
      },
    },
    {
      key: "expires_at",
      header: "Expires",
      sortable: true,
      align: "left" as const,
      render: (item: PermissionApproval) => {
        if (!item.expires_at) return <span className="text-sm text-muted-foreground">Never</span>;
        const expiresAt = new Date(item.expires_at);
        const isExpired = expiresAt < new Date();
        return (
          <span
            className={`text-sm ${isExpired ? "text-red-500" : "text-muted-foreground"}`}
            title={expiresAt.toLocaleString()}
          >
            {isExpired ? "Expired" : formatRelativeTime(item.expires_at)}
          </span>
        );
      },
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      align: "center" as const,
      render: (item: PermissionApproval) => {
        if (item.status !== "approved") return null;
        return (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-red-600 hover:text-red-700 hover:bg-red-500/10"
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              setRevokeDialog(item);
            }}
          >
            <Trash className="h-4 w-4" />
          </Button>
        );
      },
    },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Permission History</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Audit trail of all permission decisions
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

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex-1 min-w-[200px] max-w-md">
          <SearchBar
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search by agent ID or DID..."
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
            <SelectItem value="revoked">Revoked</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="expired">Expired</SelectItem>
          </SelectContent>
        </Select>
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

      {/* Stats */}
      <div className="text-sm text-muted-foreground">
        Showing {filteredPermissions.length} of {permissions.length} permissions
      </div>

      {/* Table */}
      <div className="flex-1 min-h-0">
        <CompactTable
          data={filteredPermissions}
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
            title: "No permissions found",
            description: statusFilter !== "all"
              ? `No ${statusFilter} permissions match your search.`
              : "No permission records found.",
          }}
        />
      </div>

      {/* Revoke Dialog */}
      <Dialog open={!!revokeDialog} onOpenChange={() => setRevokeDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Permission</DialogTitle>
            <DialogDescription>
              Remove access for <span className="font-mono">{revokeDialog?.caller_agent_id}</span> to call{" "}
              <span className="font-mono">{revokeDialog?.target_agent_id}</span>
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="revoke-reason">Reason (optional)</Label>
              <Input
                id="revoke-reason"
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                placeholder="Explain why this permission is being revoked..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeDialog(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRevoke} disabled={actionLoading}>
              {actionLoading ? "Revoking..." : "Revoke Permission"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
