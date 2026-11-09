'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { AgentActivityTable } from '@/components/dashboard/tenant-detail/sections/agents/activity/agent-activity-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { deriveErrorMessage, getAgentActivity, getApiErrorMessage } from '@/lib/api';
import type { AgentActivitySortField } from '@/types/activity';

export function ActivitySection() {
  const t = useTranslations('dashboard.agents.activity');
  const tErrors = useTranslations('common.errors');
  const { agentId, orgSlug, tenantSlug } = useAgentRouteParams();
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<AgentActivitySortField>({
    initialRowsPerPage: 50,
    initialSortDirection: 'desc',
    initialSortField: 'occurred_at',
  });

  const {
    data: activity,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () =>
      getAgentActivity(orgSlug ?? '', tenantSlug, agentId, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'agent-activity',
      orgSlug,
      tenantSlug,
      agentId,
      rowsPerPage,
      after,
      sortField,
      sortDirection,
    ],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  return (
    <DashboardDataCard
      description={t('description')}
      errorMessage={errorMessage}
      title={t('title')}
    >
      <AgentActivityTable
        events={activity?.items ?? []}
        isLoading={isLoading}
        sortDirection={sortDirection}
        sortField={sortField}
        onSortChange={handleSortChange}
      />

      <DashboardPagination
        currentPage={currentPage}
        itemCount={activity?.items.length ?? 0}
        nextCursor={activity?.nextCursor ?? null}
        onNext={handleNextPage}
        onPrevious={handlePreviousPage}
        onRowsPerPageChange={handleRowsPerPageChange}
        rowsPerPage={rowsPerPage}
        rowsPerPageSelectId="agent-activity-rows-per-page"
      />
    </DashboardDataCard>
  );
}
