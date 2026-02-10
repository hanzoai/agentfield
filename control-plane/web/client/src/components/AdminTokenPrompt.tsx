import { useState } from "react";
import type { FormEvent } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * Inline prompt shown on admin pages for managing the admin token.
 * Always visible: shows a form when no token is set, or a compact
 * status bar with change/clear actions when a token is active.
 */
export function AdminTokenPrompt({ onTokenSet }: { onTokenSet?: () => void }) {
  const { adminToken, setAdminToken } = useAuth();
  const [inputToken, setInputToken] = useState("");
  const [editing, setEditing] = useState(false);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!inputToken.trim()) return;
    setAdminToken(inputToken.trim());
    setInputToken("");
    setEditing(false);
    onTokenSet?.();
  };

  const handleClear = () => {
    setAdminToken(null);
    setInputToken("");
    setEditing(false);
  };

  // Token is set — show compact status with change/clear actions
  if (adminToken && !editing) {
    return (
      <div className="flex items-center gap-3 text-sm text-muted-foreground px-1 py-1.5">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-green-500" />
          Admin token set
        </span>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setEditing(true)}>
          Change
        </Button>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs text-muted-foreground" onClick={handleClear}>
          Clear
        </Button>
      </div>
    );
  }

  // No token or editing — show the input form
  return (
    <Alert className="border-amber-500/30 bg-amber-500/5">
      <AlertDescription>
        <div className="flex items-center gap-2">
          <span className="text-sm text-amber-600 font-medium shrink-0">Admin Token</span>
          <form onSubmit={handleSubmit} className="flex items-center gap-2 flex-1">
            <Input
              type="password"
              value={inputToken}
              onChange={(e) => setInputToken(e.target.value)}
              placeholder="Enter admin token"
              className="max-w-xs h-8"
              autoFocus={editing}
            />
            <Button type="submit" size="sm" className="h-8" disabled={!inputToken.trim()}>
              Set
            </Button>
            {editing && (
              <Button type="button" variant="ghost" size="sm" className="h-8" onClick={() => setEditing(false)}>
                Cancel
              </Button>
            )}
          </form>
        </div>
      </AlertDescription>
    </Alert>
  );
}
