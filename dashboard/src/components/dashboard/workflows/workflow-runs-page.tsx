'use client';

import { useState } from 'react';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { RunsTable } from '@/components/dashboard/workflows/runs-table';
import { StartRunModal } from '@/components/dashboard/workflows/start-run-modal';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import { deriveErrorMessage, getApiErrorMessage, getWorkflow, getWorkflowRuns } from '@/lib/api';
import type { ExecutionKind } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

/** One workflow's runs and, apart from them, its tests. */
export default function WorkflowRunsPage() {
  const t = useTranslations('dashboard.workflows.workflowRuns');
  const tErrors = useTranslations('common.errors');
  const navLabels = useNavLabels();
  const params = useParams<{ workflowId: string }>();
  const workflowId = decodeURIComponent(params.workflowId);
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);
  const [kind, setKind] = useState<ExecutionKind>('real');
  const [isStarting, setIsStarting] = useState(false);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    resetToFirstPage,
    rowsPerPage,
  } = useTableQueryState<never>();
  const { data: workflow } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getWorkflow(orgSlug ?? '', tenantSlug, workflowId),
    queryKey: ['workflow', orgSlug, tenantSlug, workflowId],
  });
  const {
    data: runs,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getWorkflowRuns(orgSlug ?? '', tenantSlug, workflowId, { after, kind, limit: rowsPerPage }),
    queryKey: ['workflow-runs', orgSlug, tenantSlug, workflowId, kind, after, rowsPerPage],
    refetchInterval: (query) =>
      query.state.data?.items.some((run) => run.status === 'running') ? 15_000 : false,
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const workflowsPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'workflows',
    'workflows',
  );
  const canStart =
    workflow?.status === 'published' &&
    workflow.trigger.type === 'manual' &&
    hasPermission('Workflows', 'Run');
  const name = workflow?.name ?? t('fallbackName');
  const headerTrail = isTenantView
    ? [{ href: workflowsPath, icon: 'account_tree' }, { title: name }, { title: t('title') }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview'),
          title: companyDisplayName,
        },
        { href: workflowsPath, title: navLabels.label('Workflows') },
        { title: name },
        { title: t('title') },
      ];

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Workflows"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <DashboardDataCard
            actionLabel={t('start')}
            description={t('description', { name })}
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
            title={t('title')}
            titleControl={
              <SegmentedControl
                ariaLabel={t('kindLabel')}
                onChange={(next) => {
                  setKind(next);
                  resetToFirstPage();
                }}
                options={[
                  { label: t('kindReal'), value: 'real' },
                  { label: t('kindTests'), value: 'tests' },
                ]}
                value={kind}
              />
            }
            onActionClick={canStart ? () => setIsStarting(true) : undefined}
          >
            <RunsTable
              emptyMessage={kind === 'tests' ? t('emptyTests') : t('empty')}
              isLoading={isLoading}
              runs={runs?.items ?? []}
            />
          </DashboardDataCard>
        </main>
      </div>

      <StartRunModal
        workflow={isStarting ? (workflow ?? null) : null}
        onClose={() => setIsStarting(false)}
      />
    </div>
  );
}
