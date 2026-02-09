/**
 * Local verification for AgentField SDK (TypeScript).
 *
 * Provides decentralized verification of incoming requests by caching policies,
 * revocation lists, and the admin's Ed25519 public key from the control plane.
 */

import { createHash } from 'node:crypto';
import axios, { type AxiosInstance } from 'axios';

export interface PolicyEntry {
  name: string;
  caller_tags: string[];
  target_tags: string[];
  allow_functions: string[];
  deny_functions: string[];
  constraints: Record<string, ConstraintEntry>;
  action: string;
  priority: number;
  enabled?: boolean;
}

export interface ConstraintEntry {
  operator: string;
  value: number;
}

export class LocalVerifier {
  private readonly agentFieldUrl: string;
  private readonly refreshInterval: number;
  private readonly timestampWindow: number;
  private readonly apiKey?: string;

  private policies: PolicyEntry[] = [];
  private revokedDids: Set<string> = new Set();
  private adminPublicKeyBytes: Uint8Array | null = null;
  private issuerDid: string | null = null;
  private lastRefresh = 0;
  private initialized = false;

  constructor(
    agentFieldUrl: string,
    refreshInterval = 300,
    timestampWindow = 300,
    apiKey?: string,
  ) {
    this.agentFieldUrl = agentFieldUrl.replace(/\/+$/, '');
    this.refreshInterval = refreshInterval;
    this.timestampWindow = timestampWindow;
    this.apiKey = apiKey;
  }

  get needsRefresh(): boolean {
    return Date.now() / 1000 - this.lastRefresh > this.refreshInterval;
  }

  async refresh(): Promise<boolean> {
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    let success = true;

    // Fetch policies
    try {
      const resp = await axios.get(`${this.agentFieldUrl}/api/v1/policies`, {
        headers,
        timeout: 10_000,
      });
      if (resp.status !== 200) {
        success = false;
      } else {
        this.policies = resp.data?.policies ?? [];
      }
    } catch {
      success = false;
    }

    // Fetch revocations
    try {
      const resp = await axios.get(`${this.agentFieldUrl}/api/v1/revocations`, {
        headers,
        timeout: 10_000,
      });
      if (resp.status !== 200) {
        success = false;
      } else {
        this.revokedDids = new Set(resp.data?.revoked_dids ?? []);
      }
    } catch {
      success = false;
    }

    // Fetch admin public key
    try {
      const resp = await axios.get(`${this.agentFieldUrl}/api/v1/admin/public-key`, {
        headers,
        timeout: 10_000,
      });
      if (resp.status !== 200) {
        success = false;
      } else {
        const jwk = resp.data?.public_key_jwk;
        this.issuerDid = resp.data?.issuer_did ?? null;

        if (jwk?.x) {
          // Decode base64url public key (Node 15.7+ supports 'base64url' natively)
          this.adminPublicKeyBytes = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
        }
      }
    } catch {
      success = false;
    }

    if (success) {
      this.lastRefresh = Date.now() / 1000;
      this.initialized = true;
    }

    return success;
  }

  checkRevocation(callerDid: string): boolean {
    return this.revokedDids.has(callerDid);
  }

  async verifySignature(
    callerDid: string,
    signatureB64: string,
    timestamp: string,
    body: Buffer,
  ): Promise<boolean> {
    // Validate timestamp window
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts)) return false;

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > this.timestampWindow) return false;

    if (!this.adminPublicKeyBytes || this.adminPublicKeyBytes.length !== 32) {
      return false;
    }

    try {
      const { createPublicKey, verify } = await import('node:crypto');

      // Reconstruct the signed payload: "{timestamp}:{sha256(body)}"
      const bodyHash = createHash('sha256').update(body).digest('hex');
      const payload = Buffer.from(`${timestamp}:${bodyHash}`, 'utf-8');

      // Decode the signature
      const signatureBytes = Buffer.from(signatureB64, 'base64');

      // Create Ed25519 public key object
      const publicKey = createPublicKey({
        key: Buffer.concat([
          // Ed25519 DER prefix for a 32-byte public key
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(this.adminPublicKeyBytes),
        ]),
        format: 'der',
        type: 'spki',
      });

      return verify(null, payload, publicKey, signatureBytes);
    } catch {
      return false;
    }
  }

  evaluatePolicy(
    callerTags: string[],
    targetTags: string[],
    functionName: string,
    inputParams?: Record<string, any>,
  ): boolean {
    if (!this.policies || this.policies.length === 0) {
      return false; // No policies — fail closed
    }

    // Sort by priority descending
    const sorted = [...this.policies].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));

    for (const policy of sorted) {
      if (policy.enabled === false) continue;

      // Check caller tags match
      if (policy.caller_tags?.length > 0) {
        if (!policy.caller_tags.some((t) => callerTags.includes(t))) continue;
      }

      // Check target tags match
      if (policy.target_tags?.length > 0) {
        if (!policy.target_tags.some((t) => targetTags.includes(t))) continue;
      }

      // Check deny functions first
      if (policy.deny_functions?.length > 0 && functionMatches(functionName, policy.deny_functions)) {
        return false;
      }

      // Check allow functions
      if (policy.allow_functions?.length > 0 && !functionMatches(functionName, policy.allow_functions)) {
        continue;
      }

      // Check constraints
      if (policy.constraints && inputParams) {
        if (!evaluateConstraints(policy.constraints, inputParams)) {
          return false;
        }
      }

      const action = policy.action || 'allow';
      return action === 'allow';
    }

    return false; // No matching policy — fail closed
  }
}

function functionMatches(name: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === '*') return true;
    if (pattern.endsWith('*') && name.startsWith(pattern.slice(0, -1))) return true;
    if (pattern.startsWith('*') && name.endsWith(pattern.slice(1))) return true;
    if (name === pattern) return true;
  }
  return false;
}

function evaluateConstraints(
  constraints: Record<string, ConstraintEntry>,
  inputParams: Record<string, any>,
): boolean {
  for (const [paramName, constraint] of Object.entries(constraints)) {
    if (!(paramName in inputParams)) continue;

    const value = Number(inputParams[paramName]);
    const threshold = Number(constraint.value);
    if (isNaN(value) || isNaN(threshold)) return false;

    switch (constraint.operator) {
      case '<=':
        if (value > threshold) return false;
        break;
      case '>=':
        if (value < threshold) return false;
        break;
      case '<':
        if (value >= threshold) return false;
        break;
      case '>':
        if (value <= threshold) return false;
        break;
      case '==':
        if (Math.abs(value - threshold) > 1e-9) return false;
        break;
    }
  }
  return true;
}
