import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import type { Approval, ApprovalStatus } from '@/types/approval';

type ApproverResponse = {
  display_name?: string | null;
  id: string;
};

type ApprovalResponse = {
  action: string;
  agent_id: string;
  approvers_needed?: number | null;
  decided_at?: string | null;
  delegation_id?: string | null;
  expires_at: string;
  first_approved_by?: ApproverResponse | null;
  id: string;
  pending_arguments?: string | null;
  pending_tool?: string | null;
  purpose?: string | null;
  requested_by?: ApproverResponse | null;
  run_id?: string | null;
  status: string;
};

function toApprovalStatus(value: string): ApprovalStatus {
  const normalized = value?.toLowerCase();

  if (normalized === 'approved') {
    return 'Approved';
  }

  if (normalized === 'denied') {
    return 'Denied';
  }

  if (normalized === 'expired') {
    return 'Expired';
  }

  return 'AwaitingApproval';
}

function toApproval(response: ApprovalResponse): Approval {
  return {
    action: response.action,
    agentId: response.agent_id,
    approversNeeded: response.approvers_needed ?? 1,
    decidedAt: response.decided_at ?? undefined,
    delegationId: response.delegation_id ?? '',
    firstApprovedBy: response.first_approved_by
      ? (response.first_approved_by.display_name ?? response.first_approved_by.id)
      : undefined,
    pendingArguments: response.pending_arguments ?? undefined,
    pendingTool: response.pending_tool ?? undefined,
    expiresAt: response.expires_at,
    id: response.id,
    purpose: response.purpose ?? undefined,
    requestedBy: response.requested_by
      ? (response.requested_by.display_name ?? response.requested_by.id)
      : undefined,
    runId: response.run_id ?? undefined,
    status: toApprovalStatus(response.status),
  };
}

function getAgentApprovalsEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/approvals`;
}

export async function getAgentApprovals(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<Approval[]> {
  const response = await getList<ApprovalResponse[]>(
    getAgentApprovalsEndpoint(orgSlug, tenantSlug, agentId),
  );

  return response.map(toApproval);
}

export async function approveAgentApproval(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  approvalId: string,
): Promise<Approval> {
  const response = await apiClient.post<ApprovalResponse>(
    `${getAgentApprovalsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(approvalId)}/approve`,
  );

  return toApproval(response.data);
}

export async function denyAgentApproval(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  approvalId: string,
): Promise<Approval> {
  const response = await apiClient.post<ApprovalResponse>(
    `${getAgentApprovalsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(approvalId)}/deny`,
  );

  return toApproval(response.data);
}
