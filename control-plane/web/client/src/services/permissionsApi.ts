/**
 * Permission System API
 * API client for VC-based authorization endpoints
 */

import { getGlobalApiKey } from './api';
import type {
  PermissionApproval,
  PermissionListResponse,
  PermissionApproveRequest,
  PermissionRejectRequest,
  PermissionRevokeRequest,
  ProtectedAgentRule,
  ProtectedAgentListResponse,
  ProtectedAgentRuleRequest,
} from '../types/permissions';

const API_BASE = '/api/v1';

async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const apiKey = getGlobalApiKey();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (apiKey) {
    (headers as Record<string, string>)['X-Api-Key'] = apiKey;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || `HTTP ${response.status}`);
  }

  return response;
}

// Permission Management APIs

export async function listPendingPermissions(): Promise<PermissionListResponse> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions/pending`);
  return response.json();
}

export async function listAllPermissions(): Promise<PermissionListResponse> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions`);
  return response.json();
}

export async function getPermission(id: number): Promise<PermissionApproval> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions/${id}`);
  return response.json();
}

export async function approvePermission(
  id: number,
  req: PermissionApproveRequest = {}
): Promise<PermissionApproval> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
  return response.json();
}

export async function rejectPermission(
  id: number,
  req: PermissionRejectRequest = {}
): Promise<PermissionApproval> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions/${id}/reject`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
  return response.json();
}

export async function revokePermission(
  id: number,
  req: PermissionRevokeRequest = {}
): Promise<PermissionApproval> {
  const response = await fetchWithAuth(`${API_BASE}/admin/permissions/${id}/revoke`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
  return response.json();
}

// Protected Agent Rules APIs

export async function listProtectedAgentRules(): Promise<ProtectedAgentListResponse> {
  const response = await fetchWithAuth(`${API_BASE}/admin/protected-agents`);
  return response.json();
}

export async function addProtectedAgentRule(
  req: ProtectedAgentRuleRequest
): Promise<ProtectedAgentRule> {
  const response = await fetchWithAuth(`${API_BASE}/admin/protected-agents`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
  return response.json();
}

export async function removeProtectedAgentRule(id: number): Promise<void> {
  await fetchWithAuth(`${API_BASE}/admin/protected-agents/${id}`, {
    method: 'DELETE',
  });
}
