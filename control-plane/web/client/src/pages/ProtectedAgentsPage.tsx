import { useCallback, useEffect, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Plus,
  Trash,
  Renew,
  CheckCircle,
  XCircle,
  Shield,
} from "@/components/ui/icon-bridge";
import { CompactTable } from "@/components/ui/CompactTable";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import * as permissionsApi from "../services/permissionsApi";
import type { ProtectedAgentRule, ProtectedAgentPatternType } from "../types/permissions";
import { formatRelativeTime } from "../utils/dateFormat";

const GRID_TEMPLATE = "100px minmax(200px,2fr) minmax(250px,3fr) minmax(120px,1fr) 80px";

const PATTERN_TYPE_CONFIG: Record<ProtectedAgentPatternType, { label: string; description: string; color: string }> = {
  tag: {
    label: "Tag",
    description: "Exact tag match",
    color: "bg-blue-500/10 text-blue-600 border-blue-500/30",
  },
  tag_pattern: {
    label: "Tag Pattern",
    description: "Wildcard tag match (e.g., finance*)",
    color: "bg-purple-500/10 text-purple-600 border-purple-500/30",
  },
  agent_id: {
    label: "Agent ID",
    description: "Specific agent by ID",
    color: "bg-orange-500/10 text-orange-600 border-orange-500/30",
  },
};

export function ProtectedAgentsPage() {
  const [rules, setRules] = useState<ProtectedAgentRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Sort state
  const [sortBy, setSortBy] = useState("created_at");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Add dialog
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newPatternType, setNewPatternType] = useState<ProtectedAgentPatternType>("tag");
  const [newPattern, setNewPattern] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [addLoading, setAddLoading] = useState(false);

  // Delete confirmation
  const [deleteRule, setDeleteRule] = useState<ProtectedAgentRule | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await permissionsApi.listProtectedAgentRules();
      setRules(response.rules || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load protected agent rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // Auto-dismiss success message
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  const handleAdd = async () => {
    if (!newPattern.trim()) {
      setError("Pattern is required");
      return;
    }

    setAddLoading(true);
    setError(null);
    try {
      await permissionsApi.addProtectedAgentRule({
        pattern_type: newPatternType,
        pattern: newPattern.trim(),
        description: newDescription.trim() || undefined,
      });
      setSuccess(`Added protection rule: ${newPatternType} = "${newPattern}"`);
      setShowAddDialog(false);
      setNewPatternType("tag");
      setNewPattern("");
      setNewDescription("");
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add rule");
    } finally {
      setAddLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteRule) return;
    setDeleteLoading(true);
    try {
      await permissionsApi.removeProtectedAgentRule(deleteRule.id);
      setSuccess(`Removed protection rule: ${deleteRule.pattern_type} = "${deleteRule.pattern}"`);
      setDeleteRule(null);
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule");
    } finally {
      setDeleteLoading(false);
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
      key: "pattern_type",
      header: "Type",
      sortable: false,
      align: "center" as const,
      render: (item: ProtectedAgentRule) => {
        const config = PATTERN_TYPE_CONFIG[item.pattern_type];
        return (
          <Badge variant="outline" className={config.color}>
            {config.label}
          </Badge>
        );
      },
    },
    {
      key: "pattern",
      header: "Pattern",
      sortable: true,
      align: "left" as const,
      render: (item: ProtectedAgentRule) => (
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-muted-foreground" />
          <code className="text-sm bg-muted px-2 py-0.5 rounded">{item.pattern}</code>
        </div>
      ),
    },
    {
      key: "description",
      header: "Description",
      sortable: false,
      align: "left" as const,
      render: (item: ProtectedAgentRule) => (
        <span className="text-sm text-muted-foreground truncate">
          {item.description || "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      align: "left" as const,
      render: (item: ProtectedAgentRule) => (
        <span className="text-sm text-muted-foreground" title={new Date(item.created_at).toLocaleString()}>
          {formatRelativeTime(item.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      align: "center" as const,
      render: (item: ProtectedAgentRule) => (
        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-red-600 hover:text-red-700 hover:bg-red-500/10"
          onClick={(e: React.MouseEvent) => {
            e.stopPropagation();
            setDeleteRule(item);
          }}
        >
          <Trash className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Protected Agents</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Configure which agents require permission to be called
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchRules}
            disabled={loading}
          >
            <Renew className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Add Rule
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Protected Agent Rule</DialogTitle>
                <DialogDescription>
                  Define a pattern to protect agents from unauthorized calls
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label htmlFor="pattern-type">Pattern Type</Label>
                  <Select value={newPatternType} onValueChange={(v) => setNewPatternType(v as ProtectedAgentPatternType)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(PATTERN_TYPE_CONFIG).map(([key, config]) => (
                        <SelectItem key={key} value={key}>
                          <div className="flex flex-col">
                            <span>{config.label}</span>
                            <span className="text-xs text-muted-foreground">{config.description}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="pattern">Pattern</Label>
                  <Input
                    id="pattern"
                    value={newPattern}
                    onChange={(e) => setNewPattern(e.target.value)}
                    placeholder={
                      newPatternType === "tag"
                        ? "admin"
                        : newPatternType === "tag_pattern"
                        ? "finance*"
                        : "payment-gateway"
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    {newPatternType === "tag" && "Enter the exact tag name to match"}
                    {newPatternType === "tag_pattern" && "Use * for wildcards (e.g., 'finance*' matches 'finance-core', 'finance-api')"}
                    {newPatternType === "agent_id" && "Enter the exact agent ID to protect"}
                  </p>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="description">Description (optional)</Label>
                  <Input
                    id="description"
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Why is this agent protected?"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowAddDialog(false)}>
                  Cancel
                </Button>
                <Button onClick={handleAdd} disabled={addLoading || !newPattern.trim()}>
                  {addLoading ? "Adding..." : "Add Rule"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
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

      {/* Info panel */}
      <div className="bg-muted/50 border rounded-lg p-4">
        <h3 className="font-medium mb-2 flex items-center gap-2">
          <Shield className="h-4 w-4" />
          How Protection Rules Work
        </h3>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li>• <strong>Tag:</strong> Protects all agents with an exact tag match</li>
          <li>• <strong>Tag Pattern:</strong> Protects agents with tags matching a wildcard pattern</li>
          <li>• <strong>Agent ID:</strong> Protects a specific agent by its ID</li>
          <li>• When an agent matches a protection rule, callers must have approved permission to invoke it</li>
        </ul>
      </div>

      {/* Stats */}
      <div className="text-sm text-muted-foreground">
        {rules.length} protection rule{rules.length !== 1 ? "s" : ""} configured
      </div>

      {/* Table */}
      <div className="flex-1 min-h-0">
        <CompactTable
          data={rules}
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
            title: "No protection rules",
            description: "Add a rule to require permission for calling specific agents.",
          }}
        />
      </div>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteRule} onOpenChange={() => setDeleteRule(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Protection Rule</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove this protection rule? Agents matching this pattern will no longer require permission to be called.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="bg-muted rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Badge variant="outline" className={deleteRule ? PATTERN_TYPE_CONFIG[deleteRule.pattern_type].color : ""}>
                  {deleteRule?.pattern_type}
                </Badge>
              </div>
              <code className="text-sm">{deleteRule?.pattern}</code>
              {deleteRule?.description && (
                <p className="text-sm text-muted-foreground mt-2">{deleteRule.description}</p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteRule(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleteLoading}>
              {deleteLoading ? "Deleting..." : "Delete Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
