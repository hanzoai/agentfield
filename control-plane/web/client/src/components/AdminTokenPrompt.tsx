import { useState } from "react";
import type { FormEvent } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * Inline prompt shown on permission/admin pages when the user gets a "forbidden" error.
 * Lets them enter the admin token without logging out and back in.
 */
export function AdminTokenPrompt({ onTokenSet }: { onTokenSet?: () => void }) {
  const { adminToken, setAdminToken } = useAuth();
  const [inputToken, setInputToken] = useState("");
  const [expanded, setExpanded] = useState(!adminToken);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!inputToken.trim()) return;
    setAdminToken(inputToken.trim());
    setInputToken("");
    setExpanded(false);
    onTokenSet?.();
  };

  if (adminToken && !expanded) {
    return null;
  }

  return (
    <Alert className="border-amber-500/30 bg-amber-500/5">
      <AlertTitle className="text-amber-600">Admin Token Required</AlertTitle>
      <AlertDescription>
        <p className="text-sm text-muted-foreground mb-3">
          Permission management routes require an admin token. Enter it below to access these features.
        </p>
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <Input
            type="password"
            value={inputToken}
            onChange={(e) => setInputToken(e.target.value)}
            placeholder="Admin token"
            className="max-w-xs"
          />
          <Button type="submit" size="sm" disabled={!inputToken.trim()}>
            Set Token
          </Button>
        </form>
      </AlertDescription>
    </Alert>
  );
}
