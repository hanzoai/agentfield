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
import * as policiesApi from "../services/accessPoliciesApi";
import type { AccessPolicy, AccessPolicyRequest } from "../services/accessPoliciesApi";

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Access Policies</h2>
          <p className="text-muted-foreground">
            Manage tag-based access policies for cross-agent calls
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchPolicies} disabled={loading}>
            <Renew className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button size="sm" onClick={openCreate}>
            Create Policy
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <AlertTitle>Success</AlertTitle>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Renew className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : policies.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          No access policies configured. Create one to enable tag-based authorization.
        </div>
      ) : (
        <div className="rounded-md border">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="h-10 px-4 text-left text-sm font-medium">Name</th>
                <th className="h-10 px-4 text-left text-sm font-medium">Caller Tags</th>
                <th className="h-10 px-4 text-left text-sm font-medium">Target Tags</th>
                <th className="h-10 px-4 text-left text-sm font-medium">Action</th>
                <th className="h-10 px-4 text-left text-sm font-medium">Priority</th>
                <th className="h-10 px-4 text-right text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-b">
                  <td className="px-4 py-3">
                    <div className="font-medium">{p.name}</div>
                    {p.description && (
                      <div className="text-xs text-muted-foreground">{p.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {p.caller_tags.map((t) => (
                        <Badge key={t} variant="secondary">{t}</Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {p.target_tags.map((t) => (
                        <Badge key={t} variant="outline">{t}</Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={p.action === "allow" ? "default" : "destructive"}>
                      {p.action}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-sm">{p.priority}</td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => openEdit(p)}>
                        Edit
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => setDeleteId(p.id)}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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
