'use client';

import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { RunsTable } from '@/components/dashboard/workflows/runs-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getWorkflows,
  getWorkflowExecutions,
} from '@/lib/api';

const WORKFLOW_NAMES_PAGE = 100;

/** Every run in the tenant, newest first. Reads the workflows only to name them. */
export function RunsCard({ tabs }: { tabs: ReactNode }) {
  const t = useTranslations('dashboard.workflows.runs');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    rowsPerPage,
  } = useTableQueryState<never>();
  const {
    data: runs,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getWorkflowExecutions(orgSlug ?? '', tenantSlug, { after, limit: rowsPerPage }),
    queryKey: ['workflow-runs', orgSlug, tenantSlug, after, rowsPerPage],
    refetchInterval: (query) =>
      query.state.data?.items.some((run) => run.status === 'running') ? 15_000 : false,
  });
  const { data: workflows } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getWorkflows(orgSlug ?? '', tenantSlug, { limit: WORKFLOW_NAMES_PAGE }),
    queryKey: ['workflow-names', orgSlug, tenantSlug],
  });
  const namesByWorkflow = new Map(
    (workflows?.items ?? []).map((workflow) => [workflow.id, workflow.name]),
  );
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  return (
    <DashboardDataCard
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          itemCount={runs?.items.length ?? 0}
          nextCursor={runs?.nextCursor ?? null}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="workflow-runs-rows-per-page"
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      }
      tabs={tabs}
      title={t('title')}
    >
      <RunsTable
        emptyMessage={t('empty')}
        isLoading={isLoading}
        namesByWorkflow={namesByWorkflow}
        runs={runs?.items ?? []}
      />
    </DashboardDataCard>
  );
}
