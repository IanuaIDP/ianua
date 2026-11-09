'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { ServicesTable } from '@/components/dashboard/tenant-detail/sections/services/services-table';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deleteTenantService,
  deriveErrorMessage,
  getApiErrorMessage,
  getTenantServices,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type {
  GatewayService,
  GatewayServiceAction,
  GatewayServiceSortField,
} from '@/types/gateway-service';
import {
  getCreateServiceManagementPath,
  getCreateServicePath,
  getEditServiceManagementPath,
  getEditServicePath,
} from '@/utils/dashboard-routes';

export function ServicesCard() {
  const t = useTranslations('dashboard.services');
  const tErrors = useTranslations('common.errors');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canCreateService = hasPermission('Routing', 'Create');
  const canUpdateService = hasPermission('Routing', 'Update');
  const canDeleteService = hasPermission('Routing', 'Delete');
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
  } = useTableQueryState<GatewayServiceSortField>();

  const createServicePath =
    isTenantView && orgSlug
      ? getCreateServicePath(orgSlug, tenantSlug)
      : getCreateServiceManagementPath(tenantSlug);

  function getEditPath(serviceId: string) {
    return isTenantView && orgSlug
      ? getEditServicePath(orgSlug, tenantSlug, serviceId)
      : getEditServiceManagementPath(tenantSlug, serviceId);
  }

  const {
    data: servicesList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () =>
      getTenantServices(orgSlug ?? '', tenantSlug, {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'tenant-services',
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

  async function handleServiceAction(service: GatewayService, action: GatewayServiceAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    if (action !== 'Delete') {
      return;
    }

    await deleteTenantService(orgSlug, tenantSlug, service.id);
    await queryClient.invalidateQueries({ queryKey: ['tenant-services', orgSlug, tenantSlug] });
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
          rowsPerPageSelectId="tenant-services-rows-per-page"
          itemCount={servicesList?.items.length ?? 0}
          nextCursor={servicesList?.nextCursor ?? null}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      }
      title={t('title')}
      onActionClick={canCreateService ? () => router.push(createServicePath) : undefined}
    >
      <ServicesTable
        canDeleteService={canDeleteService}
        canUpdateService={canUpdateService}
        isLoading={isLoading}
        services={servicesList?.items ?? []}
        sortDirection={sortDirection}
        sortField={sortField}
        onEditClick={(service) => router.push(getEditPath(service.id))}
        onServiceAction={handleServiceAction}
        onSortChange={handleSortChange}
      />
    </DashboardDataCard>
  );
}
