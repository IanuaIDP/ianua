'use client';

import type { ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { RoutesTable } from '@/components/dashboard/tenant-detail/sections/routes/routes-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { useNotification } from '@/components/ui/notifications';
import {
  activateTenantPipeline,
  createTenantPipeline,
  createTenantRoute,
  createTenantService,
  deriveErrorMessage,
  executeRouteAction,
  getApiErrorMessage,
  getTenantPipelines,
  getTenantRoutes,
  getTenantServices,
  isConflictError,
} from '@/lib/api';
import {
  EXAMPLE_PIPELINE_NAME,
  EXAMPLE_SERVICE_NAME,
  EXAMPLE_UPSTREAM_URL,
  buildExampleRoute,
  buildExampleService,
} from '@/constants/example-route';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Route, RouteAction, RouteSortField } from '@/types/route';
import {
  getCreateRoutePath,
  getCreateRouteManagementPath,
  getEditRoutePath,
  getEditRouteManagementPath,
} from '@/utils/dashboard-routes';

type HttpRoutesCardProps = {
  titleControl?: ReactNode;
};

export function HttpRoutesCard({ titleControl }: HttpRoutesCardProps) {
  const t = useTranslations('dashboard.routes');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateRoute = hasPermission('Routing', 'Create');
  const canUpdateRoute = hasPermission('Routing', 'Update');
  const canDeleteRoute = hasPermission('Routing', 'Delete');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
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
  } = useTableQueryState<RouteSortField>();

  const createRoutePath =
    isTenantView && orgSlug
      ? getCreateRoutePath(orgSlug, tenantSlug)
      : getCreateRouteManagementPath(tenantSlug);

  function getEditPath(routeId: string) {
    return isTenantView && orgSlug
      ? getEditRoutePath(orgSlug, tenantSlug, routeId)
      : getEditRouteManagementPath(tenantSlug, routeId);
  }

  const {
    data: routesList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantRoutes(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['tenant-routes', orgSlug, tenantSlug, after, rowsPerPage, sortField, sortDirection],
  });
  const { data: pipelines } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPipelines(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-pipelines', orgSlug, tenantSlug],
  });
  const pipelineNameById = Object.fromEntries(
    (pipelines ?? []).map((pipeline) => [pipeline.id, pipeline.name]),
  );
  const { data: services } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantServices(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-services', orgSlug, tenantSlug],
  });
  const serviceNameById = Object.fromEntries(
    (services?.items ?? []).map((service) => [service.id, service.name]),
  );
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidateRoutes() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-routes', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function handleRouteAction(route: Route, action: RouteAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeRouteAction(orgSlug, tenantSlug, route, action);
    await invalidateRoutes();
  }

  // A pipeline to run, activated so it will run; a service to forward to; then
  // the route that names both. A new pipeline already carries Identity and
  // Policy, which is everything this route needs to decide anything.
  const { isPending: isAddingExample, mutate: addExampleRoute } = useMutation({
    mutationFn: async () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      const existingPipeline = (pipelines ?? []).find(
        (entry) => entry.name === EXAMPLE_PIPELINE_NAME,
      );
      const pipelineId =
        existingPipeline?.id ??
        (await createTenantPipeline(orgSlug, tenantSlug, EXAMPLE_PIPELINE_NAME));

      if (!existingPipeline) {
        await activateTenantPipeline(orgSlug, tenantSlug, pipelineId);
      }

      const existingService = (services?.items ?? []).find(
        (entry) => entry.name === EXAMPLE_SERVICE_NAME,
      );
      const serviceId =
        existingService?.id ??
        (await createTenantService(orgSlug, tenantSlug, buildExampleService(EXAMPLE_UPSTREAM_URL)));

      try {
        await createTenantRoute(orgSlug, tenantSlug, buildExampleRoute(pipelineId, serviceId));
      } catch (routeError) {
        if (isConflictError(routeError)) {
          return 'already-there' as const;
        }
        throw routeError;
      }
      return 'added' as const;
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.exampleFailed')),
        type: 'error',
      });
    },
    onSuccess: async (outcome) => {
      showNotification({
        message: outcome === 'added' ? t('toasts.exampleAdded') : t('toasts.exampleExists'),
        type: 'success',
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-services', orgSlug, tenantSlug] });
      await invalidateRoutes();
    },
  });

  return (
    <DashboardDataCard
      actionLabel={t('add')}
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="tenant-routes-rows-per-page"
          itemCount={routesList?.items.length ?? 0}
          nextCursor={routesList?.nextCursor ?? null}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      }
      isSecondaryActionDisabled={isAddingExample}
      secondaryActionLabel={isAddingExample ? t('adding') : t('addExample')}
      title={t('title')}
      titleControl={titleControl}
      onActionClick={canCreateRoute ? () => router.push(createRoutePath) : undefined}
      onSecondaryActionClick={canCreateRoute ? () => addExampleRoute() : undefined}
    >
      <RoutesTable
        canDeleteRoute={canDeleteRoute}
        canUpdateRoute={canUpdateRoute}
        isLoading={isLoading}
        pipelineNameById={pipelineNameById}
        routes={routesList?.items ?? []}
        serviceNameById={serviceNameById}
        sortDirection={sortDirection}
        sortField={sortField}
        onEditClick={(route) => router.push(getEditPath(route.id))}
        onRouteAction={handleRouteAction}
        onSortChange={handleSortChange}
      />
    </DashboardDataCard>
  );
}
