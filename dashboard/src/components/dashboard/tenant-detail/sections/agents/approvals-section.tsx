'use client';

import { useQueryClient, useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { ApprovalsTable } from '@/components/dashboard/tenant-detail/sections/agents/approvals/approvals-table';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import {
  approveAgentApproval,
  denyAgentApproval,
  deriveErrorMessage,
  getAgentApprovals,
  getApiErrorMessage,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Approval } from '@/types/approval';
import { getAgentManagementPath, getAgentPath } from '@/utils/dashboard-routes';

export function ApprovalsSection() {
  const t = useTranslations('dashboard.agents.approvals');
  const tErrors = useTranslations('common.errors');
  const { agentId, isTenantView, orgSlug, tenantSlug } = useAgentRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canReview = hasPermission('Agents', 'Approve');
  const queryClient = useQueryClient();

  const approvalsQueryKey = ['agent-approvals', orgSlug, tenantSlug, agentId];
  const agentDetailPath = isTenantView
    ? orgSlug
      ? getAgentPath(orgSlug, tenantSlug, agentId)
      : undefined
    : getAgentManagementPath(tenantSlug, agentId);
  const runsHref = agentDetailPath ? `${agentDetailPath}/runs` : '#';

  const {
    data: approvals,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getAgentApprovals(orgSlug ?? '', tenantSlug, agentId),
    queryKey: approvalsQueryKey,
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateApprovals() {
    await queryClient.invalidateQueries({ queryKey: approvalsQueryKey });
    await queryClient.invalidateQueries({ queryKey: ['agent-runs', orgSlug, tenantSlug, agentId] });

    if (orgSlug) {
      await invalidateAuditLogQueries(queryClient, orgSlug);
    }
  }

  async function handleApprove(approval: Approval) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await approveAgentApproval(orgSlug, tenantSlug, agentId, approval.id);
    await invalidateApprovals();
  }

  async function handleDeny(approval: Approval) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await denyAgentApproval(orgSlug, tenantSlug, agentId, approval.id);
    await invalidateApprovals();
  }

  return (
    <DashboardDataCard
      description={t('description')}
      errorMessage={errorMessage}
      title={t('title')}
    >
      <ApprovalsTable
        approvals={approvals ?? []}
        canReview={canReview}
        isLoading={isLoading}
        runsHref={runsHref}
        onApprove={handleApprove}
        onDeny={handleDeny}
      />
    </DashboardDataCard>
  );
}
