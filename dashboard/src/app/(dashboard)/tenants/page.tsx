'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardPageContent } from '@/components/dashboard/shared/dashboard-page-content';
import { CreateTenantModal } from '@/components/dashboard/tenants/create-tenant-modal';
import { TenantsCard } from '@/components/dashboard/tenants/tenants-card';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import {
  createTenant,
  deriveErrorMessage,
  executeTenantAction,
  getApiErrorMessage,
  getTenants,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';
import type { CreateTenantInput } from '@/lib/api';
import type { Tenant, TenantAction, TenantSortField, TenantTab } from '@/types/tenant';

const tenantTabs: TenantTab[] = ['All', 'Active', 'Provisioning', 'Suspended', 'Archived'];

export default function TenantsPage() {
  const t = useTranslations('dashboard.tenants');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const [activeTab, setActiveTab] = useState<TenantTab>('All');
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    resetToFirstPage,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<TenantSortField>();
  const [isCreateTenantModalOpen, setIsCreateTenantModalOpen] = useState(false);
  const status = activeTab === 'All' ? undefined : activeTab;
  const {
    data: tenantsList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () =>
      getTenants(organizationSlug ?? '', {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
        status,
      }),
    queryKey: ['tenants', organizationSlug, status, sortField, sortDirection, after, rowsPerPage],
    refetchInterval: (query) =>
      query.state.data?.items.some((tenant) => tenant.status === 'Provisioning') ? 3000 : false,
    staleTime: 0,
  });
  const {
    isPending: isCreatingTenant,
    mutate: submitCreateTenant,
    reset: resetCreateTenantMutation,
  } = useMutation({
    mutationFn: (payload: CreateTenantInput) => createTenant(organizationSlug ?? '', payload),
    onSuccess: async () => {
      setIsCreateTenantModalOpen(false);
      resetToFirstPage();
      showNotification({ message: t('toasts.created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['tenants', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const handleTenantAction = async (tenant: Tenant, action: TenantAction) => {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantAction(organizationSlug, tenant, action);
    await queryClient.invalidateQueries({ queryKey: ['tenants', organizationSlug] });
    await invalidateAuditLogQueries(queryClient, organizationSlug);
  };

  return (
    <div>
      <DashboardPageHeader icon="corporate_fare" title={t('title')} />
      <DashboardPageContent>
        <TenantsCard
          activeTab={activeTab}
          currentPage={currentPage}
          errorMessage={errorMessage}
          isLoading={isLoading}
          rowsPerPage={rowsPerPage}
          sortDirection={sortDirection}
          sortField={sortField}
          tabs={tenantTabs}
          tenants={tenantsList?.items ?? []}
          nextCursor={tenantsList?.nextCursor ?? null}
          onCreateTenantClick={() => {
            resetCreateTenantMutation();
            setIsCreateTenantModalOpen(true);
          }}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
          onSortChange={handleSortChange}
          onTenantAction={handleTenantAction}
          onTabChange={(tab) => {
            setActiveTab(tab);
            resetToFirstPage();
          }}
        />
      </DashboardPageContent>

      <CreateTenantModal
        isSubmitting={isCreatingTenant}
        open={isCreateTenantModalOpen}
        onClose={() => {
          resetCreateTenantMutation();
          setIsCreateTenantModalOpen(false);
        }}
        onSubmit={submitCreateTenant}
        orgSlug={organizationSlug}
      />
    </div>
  );
}
