/**
 * Permission System Types
 * Types for VC-based authorization system
 */

export type PermissionStatus = 'pending' | 'approved' | 'rejected' | 'revoked' | 'expired';

export interface PermissionApproval {
  id: number;
  caller_did: string;
  target_did: string;
  caller_agent_id: string;
  target_agent_id: string;
  status: PermissionStatus;
  effective_status: PermissionStatus;
  approved_by?: string;
  approved_at?: string;
  rejected_by?: string;
  rejected_at?: string;
  revoked_by?: string;
  revoked_at?: string;
  expires_at?: string;
  reason?: string;
  created_at: string;
  updated_at: string;
}

export type ProtectedAgentPatternType = 'tag' | 'tag_pattern' | 'agent_id';

export interface ProtectedAgentRule {
  id: number;
  pattern_type: ProtectedAgentPatternType;
  pattern: string;
  description?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PermissionListResponse {
  permissions: PermissionApproval[];
  total: number;
}

export interface ProtectedAgentListResponse {
  rules: ProtectedAgentRule[];
  total: number;
}

export interface PermissionApproveRequest {
  duration_hours?: number;
  reason?: string;
}

export interface PermissionRejectRequest {
  reason?: string;
}

export interface PermissionRevokeRequest {
  reason?: string;
}

export interface ProtectedAgentRuleRequest {
  pattern_type: ProtectedAgentPatternType;
  pattern: string;
  description?: string;
}
