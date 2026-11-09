'use client';

import type { ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { StreamRoutesTable } from '@/components/dashboard/tenant-detail/sections/routes/stream-routes-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  executeStreamRouteAction,
  getApiErrorMessage,
  getTenantStreamRoutes,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { StreamRoute, StreamRouteAction, StreamRouteSortField } from '@/types/stream-route';
import {
  getCreateStreamRoutePath,
  getCreateStreamRouteManagementPath,
  getEditStreamRoutePath,
  getEditStreamRouteManagementPath,
} from '@/utils/dashboard-routes';

type StreamRoutesCardProps = {
  titleControl?: ReactNode;
};

/**
 * The ports the proxy listens on below HTTP.
 *
 * A port carries its own backends rather than pointing at a service: a
 * service's upstream is an HTTP URL, and there is no such thing at layer 4.
 */
export function StreamRoutesCard({ titleControl }: StreamRoutesCardProps) {
  const t = useTranslations('dashboard.ports');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateRoute = hasPermission('Routing', 'Create');
  const canUpdateRoute = hasPermission('Routing', 'Update');
  const canDeleteRoute = hasPermission('Routing', 'Delete');
  const queryClient = useQueryClient();
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
  } = useTableQueryState<StreamRouteSortField>();

  const createRoutePath =
    isTenantView && orgSlug
      ? getCreateStreamRoutePath(orgSlug, tenantSlug)
      : getCreateStreamRouteManagementPath(tenantSlug);

  function getEditPath(routeId: string) {
    return isTenantView && orgSlug
      ? getEditStreamRoutePath(orgSlug, tenantSlug, routeId)
      : getEditStreamRouteManagementPath(tenantSlug, routeId);
  }

  const {
    data: routesList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantStreamRoutes(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-stream-routes',
      orgSlug,
      tenantSlug,
      after,
      rowsPerPage,
      sortField,
      sortDirection,
    ],
  });

  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function handleRouteAction(route: StreamRoute, action: StreamRouteAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeStreamRouteAction(orgSlug, tenantSlug, route, action);
    await queryClient.invalidateQueries({
      queryKey: ['tenant-stream-routes', orgSlug, tenantSlug],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <DashboardDataCard
      actionLabel={t('add')}
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="tenant-stream-routes-rows-per-page"
          itemCount={routesList?.items.length ?? 0}
          nextCursor={routesList?.nextCursor ?? null}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      }
      title={t('title')}
      titleControl={titleControl}
      onActionClick={canCreateRoute ? () => router.push(createRoutePath) : undefined}
    >
      <StreamRoutesTable
        canDeleteRoute={canDeleteRoute}
        canUpdateRoute={canUpdateRoute}
        isLoading={isLoading}
        routes={routesList?.items ?? []}
        sortDirection={sortDirection}
        sortField={sortField}
        onEditClick={(route) => router.push(getEditPath(route.id))}
        onRouteAction={handleRouteAction}
        onSortChange={handleSortChange}
      />
    </DashboardDataCard>
  );
}
