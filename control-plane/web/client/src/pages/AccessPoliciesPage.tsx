import { useCallback, useEffect, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  CheckCircle,
  XCircle,
  Renew,
  Trash,
  Plus,
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
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import * as policiesApi from "../services/accessPoliciesApi";
import type { AccessPolicy, AccessPolicyRequest } from "../services/accessPoliciesApi";
import { AdminTokenPrompt } from "../components/AdminTokenPrompt";

const GRID_TEMPLATE = "minmax(180px,2fr) minmax(140px,1.5fr) minmax(140px,1.5fr) 90px 80px 110px";

const emptyPolicy: AccessPolicyRequest = {
  name: "",
  caller_tags: [],
  target_tags: [],
  allow_functions: [],
  deny_functions: [],
  action: "allow",
  priority: 0,
  description: "",
};

export function AccessPoliciesPage() {
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Sort state
  const [sortBy, setSortBy] = useState("priority");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Create/edit dialog
  const [editPolicy, setEditPolicy] = useState<AccessPolicyRequest | null>(null);
  const [editId, setEditId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Tag input helpers
  const [callerTagInput, setCallerTagInput] = useState("");
  const [targetTagInput, setTargetTagInput] = useState("");
  const [allowFuncInput, setAllowFuncInput] = useState("");
  const [denyFuncInput, setDenyFuncInput] = useState("");

  const fetchPolicies = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await policiesApi.listPolicies();
      setPolicies(data.policies || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to fetch policies");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  // Auto-dismiss success message
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  const openCreate = () => {
    setEditPolicy({ ...emptyPolicy });
    setEditId(null);
    setCallerTagInput("");
    setTargetTagInput("");
    setAllowFuncInput("");
    setDenyFuncInput("");
  };

  const openEdit = (p: AccessPolicy) => {
    setEditPolicy({
      name: p.name,
      caller_tags: [...p.caller_tags],
      target_tags: [...p.target_tags],
      allow_functions: [...(p.allow_functions || [])],
      deny_functions: [...(p.deny_functions || [])],
      action: p.action,
      priority: p.priority,
      description: p.description || "",
    });
    setEditId(p.id);
    setCallerTagInput(p.caller_tags.join(", "));
    setTargetTagInput(p.target_tags.join(", "));
    setAllowFuncInput((p.allow_functions || []).join(", "));
    setDenyFuncInput((p.deny_functions || []).join(", "));
  };

  const parseTags = (input: string): string[] =>
    input.split(",").map(s => s.trim()).filter(Boolean);

  const handleSave = async () => {
    if (!editPolicy) return;
    try {
      setSaving(true);
      setError(null);
      const req: AccessPolicyRequest = {
        ...editPolicy,
        caller_tags: parseTags(callerTagInput),
        target_tags: parseTags(targetTagInput),
        allow_functions: parseTags(allowFuncInput),
        deny_functions: parseTags(denyFuncInput),
      };
      if (editId) {
        await policiesApi.updatePolicy(editId, req);
        setSuccess(`Policy "${req.name}" updated`);
      } else {
        await policiesApi.createPolicy(req);
        setSuccess(`Policy "${req.name}" created`);
      }
      setEditPolicy(null);
      setEditId(null);
      fetchPolicies();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save policy");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (deleteId === null) return;
    try {
      setDeleting(true);
      setError(null);
      await policiesApi.deletePolicy(deleteId);
      setSuccess("Policy deleted");
      setDeleteId(null);
      fetchPolicies();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete policy");
    } finally {
      setDeleting(false);
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
      key: "name",
      header: "Name",
      sortable: true,
      align: "left" as const,
      render: (item: AccessPolicy) => (
        <div className="min-w-0 py-1">
          <div className="font-medium text-sm truncate leading-tight">{item.name}</div>
          {item.description && (
            <div className="text-xs text-muted-foreground truncate leading-tight mt-0.5">{item.description}</div>
          )}
        </div>
      ),
    },
    {
      key: "caller_tags",
      header: "Caller Tags",
      sortable: false,
      align: "left" as const,
      render: (item: AccessPolicy) => (
        <div className="flex flex-wrap gap-1 overflow-hidden">
          {item.caller_tags.map((t) => (
            <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
          ))}
        </div>
      ),
    },
    {
      key: "target_tags",
      header: "Target Tags",
      sortable: false,
      align: "left" as const,
      render: (item: AccessPolicy) => (
        <div className="flex flex-wrap gap-1 overflow-hidden">
          {item.target_tags.map((t) => (
            <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
          ))}
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      sortable: false,
      align: "center" as const,
      render: (item: AccessPolicy) => (
        <Badge variant={item.action === "allow" ? "default" : "destructive"}>
          {item.action}
        </Badge>
      ),
    },
    {
      key: "priority",
      header: "Priority",
      sortable: true,
      align: "center" as const,
      render: (item: AccessPolicy) => (
        <span className="text-sm text-muted-foreground">{item.priority}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      align: "right" as const,
      render: (item: AccessPolicy) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs"
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              openEdit(item);
            }}
          >
            Edit
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-red-600 hover:text-red-700 hover:bg-red-500/10"
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              setDeleteId(item.id);
            }}
          >
            <Trash className="h-3.5 w-3.5" />
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
          <h1 className="text-2xl font-semibold">Access Policies</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Manage tag-based access policies for cross-agent calls
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={fetchPolicies} disabled={loading}>
            <Renew className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button size="sm" onClick={openCreate}>
            <Plus className="h-4 w-4 mr-2" />
            Create Policy
          </Button>
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

      {/* Admin token prompt — always visible when no token is set */}
      <AdminTokenPrompt onTokenSet={fetchPolicies} />

      {/* Stats */}
      <div className="text-sm text-muted-foreground">
        {policies.length} polic{policies.length !== 1 ? "ies" : "y"} configured
      </div>

      {/* Table */}
      <div className="flex-1 min-h-0">
        <CompactTable
          data={policies}
          columns={columns}
          loading={loading}
          hasMore={false}
          isFetchingMore={false}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={handleSortChange}
          gridTemplate={GRID_TEMPLATE}
          getRowKey={(item) => String(item.id)}
          rowHeight={48}
          emptyState={{
            title: "No access policies",
            description: "Create a policy to enable tag-based authorization for cross-agent calls.",
          }}
        />
      </div>

      {/* Create/Edit Dialog */}
      <Dialog open={editPolicy !== null} onOpenChange={(open) => !open && setEditPolicy(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editId ? "Edit Policy" : "Create Policy"}</DialogTitle>
            <DialogDescription>
              Define a tag-based access policy for cross-agent calls.
            </DialogDescription>
          </DialogHeader>
          {editPolicy && (
            <div className="space-y-4">
              <div>
                <Label>Name</Label>
                <Input
                  value={editPolicy.name}
                  onChange={(e) => setEditPolicy({ ...editPolicy, name: e.target.value })}
                  placeholder="finance_to_billing"
                />
              </div>
              <div>
                <Label>Caller Tags (comma-separated)</Label>
                <Input
                  value={callerTagInput}
                  onChange={(e) => setCallerTagInput(e.target.value)}
                  placeholder="finance, payment"
                />
              </div>
              <div>
                <Label>Target Tags (comma-separated)</Label>
                <Input
                  value={targetTagInput}
                  onChange={(e) => setTargetTagInput(e.target.value)}
                  placeholder="billing, internal"
                />
              </div>
              <div>
                <Label>Allow Functions (comma-separated, supports wildcards)</Label>
                <Input
                  value={allowFuncInput}
                  onChange={(e) => setAllowFuncInput(e.target.value)}
                  placeholder="charge_*, get_*"
                />
              </div>
              <div>
                <Label>Deny Functions (comma-separated, supports wildcards)</Label>
                <Input
                  value={denyFuncInput}
                  onChange={(e) => setDenyFuncInput(e.target.value)}
                  placeholder="delete_*, admin_*"
                />
              </div>
              <div className="flex gap-4">
                <div className="flex-1">
                  <Label>Action</Label>
                  <select
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
                    value={editPolicy.action}
                    onChange={(e) => setEditPolicy({ ...editPolicy, action: e.target.value as 'allow' | 'deny' })}
                  >
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </select>
                </div>
                <div className="flex-1">
                  <Label>Priority</Label>
                  <Input
                    type="number"
                    value={editPolicy.priority ?? 0}
                    onChange={(e) => setEditPolicy({ ...editPolicy, priority: parseInt(e.target.value) || 0 })}
                  />
                </div>
              </div>
              <div>
                <Label>Description</Label>
                <Input
                  value={editPolicy.description || ""}
                  onChange={(e) => setEditPolicy({ ...editPolicy, description: e.target.value })}
                  placeholder="Optional description"
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditPolicy(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "Saving..." : editId ? "Update" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteId !== null} onOpenChange={(open) => !open && setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Policy</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this access policy? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
