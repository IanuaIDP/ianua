'use client';

import { useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTabs } from '@/components/dashboard/shared/dashboard-tabs';
import { SearchInput } from '@/components/ui/search-input';
import { Select } from '@/components/ui/Select';
import { RisksCard } from '@/components/dashboard/workflows/risks/risks-card';
import { RunsCard } from '@/components/dashboard/workflows/runs-card';
import { StartRunModal } from '@/components/dashboard/workflows/start-run-modal';
import type { WorkflowAction } from '@/components/dashboard/workflows/workflow-actions-menu';
import { WorkflowsTable } from '@/components/dashboard/workflows/workflows-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  archiveWorkflowVersion,
  deriveErrorMessage,
  getApiErrorMessage,
  getWorkflows,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Workflow, WorkflowSortField } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

type WorkflowsTab = 'Workflows' | 'Runs' | 'Risks';

const WORKFLOW_TABS: WorkflowsTab[] = ['Workflows', 'Runs', 'Risks'];

function tabFromSearch(tab: string | null): WorkflowsTab {
  if (tab === 'runs') {
    return 'Runs';
  }

  return tab === 'risks' ? 'Risks' : 'Workflows';
}

function matchesSearch(workflow: Workflow, search: string, status: string) {
  const term = search.trim().toLowerCase();

  return (
    (!term || workflow.name.toLowerCase().includes(term)) &&
    (status === 'all' ? workflow.status !== 'archived' : workflow.status === status)
  );
}

export function WorkflowsCard() {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const { hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const tab = tabFromSearch(searchParams.get('tab'));
  const tabs = (
    <DashboardTabs
      activeTab={tab}
      tabs={WORKFLOW_TABS}
      onTabChange={(next) =>
        router.replace(next === 'Workflows' ? pathname : `${pathname}?tab=${next.toLowerCase()}`, {
          scroll: false,
        })
      }
    />
  );

  if (isLoadingPermissions) {
    return null;
  }

  if (!hasPermission('Workflows', 'View')) {
    return <ApprovalsOnlyNotice canApprove={hasPermission('Workflows', 'Approve')} />;
  }

  switch (tab) {
    case 'Runs':
      return <RunsCard tabs={tabs} />;
    case 'Risks':
      return <RisksCard tabs={tabs} />;
    default:
      return <WorkflowsListCard tabs={tabs} />;
  }
}

function ApprovalsOnlyNotice({ canApprove }: { canApprove: boolean }) {
  const t = useTranslations('dashboard.workflows.list');

  return (
    <section className="mx-auto w-full max-w-360 rounded-lg border border-borderGray bg-cardBg p-4 text-sm text-textGray">
      {canApprove ? t('approveOnly') : t('noView')}
    </section>
  );
}

function WorkflowsListCard({ tabs }: { tabs: ReactNode }) {
  const t = useTranslations('dashboard.workflows.list');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const queryClient = useQueryClient();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [starting, setStarting] = useState<Workflow | null>(null);
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
  } = useTableQueryState<WorkflowSortField>();
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getWorkflows(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['workflows', orgSlug, tenantSlug, after, rowsPerPage, sortDirection, sortField],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const shown = (data?.items ?? []).filter((workflow) => matchesSearch(workflow, search, status));
  const isFiltering = Boolean(search.trim()) || status !== 'all';

  function workflowPath(workflow: Workflow, segment: string) {
    return getTenantScopedPath(
      isTenantView,
      orgSlug,
      tenantSlug,
      `workflows/${workflow.id}${segment}`,
      `workflows/${workflow.id}${segment}`,
    );
  }

  async function handleRemove(workflow: Workflow) {
    await archiveWorkflowVersion(orgSlug ?? '', tenantSlug, workflow.id, workflow.version);
    await queryClient.invalidateQueries({ queryKey: ['workflows', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function handleAction(workflow: Workflow, action: WorkflowAction) {
    if (action === 'Start') {
      setStarting(workflow);
      return;
    }

    router.push(workflowPath(workflow, action === 'Runs' ? '/runs' : ''));
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={hasPermission('Workflows', 'Create') ? t('create') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        onActionClick={() =>
          router.push(
            getTenantScopedPath(
              isTenantView,
              orgSlug,
              tenantSlug,
              'workflows/create',
              'workflows/create',
            ),
          )
        }
        footer={
          <DashboardPagination
            currentPage={currentPage}
            itemCount={shown.length}
            nextCursor={data?.nextCursor ?? null}
            rowsPerPage={rowsPerPage}
            rowsPerPageSelectId="workflows-rows-per-page"
            onNext={handleNextPage}
            onPrevious={handlePreviousPage}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        }
        secondaryAction={
          <div className="flex flex-col gap-2 sm:w-96 sm:flex-row sm:items-center">
            <SearchInput
              onChange={(event) => setSearch(event.target.value)}
              onClear={() => setSearch('')}
              placeholder={t('searchPlaceholder')}
              value={search}
            />
            <Select
              containerClassName="mb-0 sm:w-44"
              onChange={setStatus}
              options={[
                { label: t('statusAll'), value: 'all' },
                { label: t('statusOn'), value: 'published' },
                { label: t('statusDraft'), value: 'draft' },
                { label: t('statusOff'), value: 'archived' },
              ]}
              value={status}
            />
          </div>
        }
        tabs={tabs}
        title={t('title')}
      >
        <WorkflowsTable
          canRemove={hasPermission('Workflows', 'Delete')}
          canRun={hasPermission('Workflows', 'Run')}
          onRemove={handleRemove}
          emptyMessage={isFiltering ? t('noMatches') : t('empty')}
          isLoading={isLoading}
          onAction={handleAction}
          onSortChange={handleSortChange}
          sortDirection={sortDirection}
          sortField={sortField}
          workflows={shown}
        />
      </DashboardDataCard>
      <StartRunModal workflow={starting} onClose={() => setStarting(null)} />
    </>
  );
}
