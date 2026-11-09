'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { FlowsTable } from '@/components/dashboard/tenant-detail/sections/flows/flows-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  executeTenantFlowAction,
  getApiErrorMessage,
  getTenantFlows,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Flow, FlowAction } from '@/types/flow';
import {
  getFlowManagementPath,
  getFlowPath,
  getTenantManagementPath,
  getTenantPath,
} from '@/utils/dashboard-routes';

export function FlowsCard() {
  const t = useTranslations('dashboard.flows');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateFlow = hasPermission('Workflows', 'Create') && hasPermission('Workflows', 'Run');
  const canCancelFlow = hasPermission('Workflows', 'Run');
  const canDeleteFlow = hasPermission('Workflows', 'Run') || hasPermission('Workflows', 'Delete');
  const queryClient = useQueryClient();
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    rowsPerPage,
  } = useTableQueryState<never>();

  const {
    data: flowsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantFlows(orgSlug ?? '', tenantSlug, { after, limit: rowsPerPage }),
    queryKey: ['tenant-flows', orgSlug, tenantSlug, after, rowsPerPage],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function handleFlowAction(flow: Flow, action: FlowAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantFlowAction(orgSlug, tenantSlug, flow, action);
    await queryClient.invalidateQueries({ queryKey: ['tenant-flows', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function handleFlowClick(flow: Flow) {
    if (!isTenantView) {
      router.push(getFlowManagementPath(tenantSlug, flow.id));
      return;
    }

    if (!orgSlug) {
      return;
    }

    router.push(getFlowPath(orgSlug, tenantSlug, flow.id));
  }

  const createFlowPath = isTenantView
    ? orgSlug
      ? `${getTenantPath(orgSlug, tenantSlug)}/flows/create`
      : undefined
    : `${getTenantManagementPath(tenantSlug)}/flows/create`;

  return (
    <DashboardDataCard
      actionLabel={t('createAction')}
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          itemCount={flowsList?.items.length ?? 0}
          nextCursor={flowsList?.nextCursor ?? null}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="tenant-flows-rows-per-page"
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      }
      title={t('title')}
      onActionClick={
        canCreateFlow && createFlowPath ? () => router.push(createFlowPath) : undefined
      }
    >
      <FlowsTable
        canCancel={canCancelFlow}
        canDelete={canDeleteFlow}
        flows={flowsList?.items ?? []}
        isLoading={isLoading}
        onFlowAction={handleFlowAction}
        onFlowClick={handleFlowClick}
      />
    </DashboardDataCard>
  );
}
