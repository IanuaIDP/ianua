'use client';

import { useTranslations } from 'next-intl';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { DashboardTabs } from '@/components/dashboard/shared/dashboard-tabs';
import { TenantsTable } from '@/components/dashboard/tenants/tenants-table';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import type {
  Tenant,
  TenantAction,
  TenantSortDirection,
  TenantSortField,
  TenantTab,
} from '@/types/tenant';

type TenantsCardProps = {
  activeTab: TenantTab;
  currentPage: number;
  errorMessage?: string;
  isLoading?: boolean;
  onCreateTenantClick: () => void;
  nextCursor: string | null;
  onNext: (nextCursor: string) => void;
  onPrevious: () => void;
  onRowsPerPageChange: (rowsPerPage: number) => void;
  onSortChange: (field: TenantSortField) => void;
  onTabChange: (tab: TenantTab) => void;
  onTenantAction: (tenant: Tenant, action: TenantAction) => Promise<void> | void;
  rowsPerPage: number;
  sortDirection?: TenantSortDirection;
  sortField?: TenantSortField;
  tabs: TenantTab[];
  tenants: Tenant[];
};

export function TenantsCard({
  activeTab,
  currentPage,
  errorMessage,
  isLoading = false,
  nextCursor,
  onCreateTenantClick,
  onNext,
  onPrevious,
  onRowsPerPageChange,
  onSortChange,
  onTabChange,
  onTenantAction,
  rowsPerPage,
  sortDirection,
  sortField,
  tabs,
  tenants,
}: TenantsCardProps) {
  const t = useTranslations('dashboard.tenants');
  const { canManageOrganization } = useOrgAccess();

  return (
    <DashboardDataCard
      actionLabel={canManageOrganization ? t('create') : undefined}
      description={t('description')}
      errorMessage={errorMessage}
      footer={
        <DashboardPagination
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="tenant-rows-per-page"
          itemCount={tenants.length}
          nextCursor={nextCursor}
          onNext={onNext}
          onPrevious={onPrevious}
          onRowsPerPageChange={onRowsPerPageChange}
        />
      }
      tabs={<DashboardTabs activeTab={activeTab} tabs={tabs} onTabChange={onTabChange} />}
      title={t('title')}
      onActionClick={canManageOrganization ? onCreateTenantClick : undefined}
    >
      <TenantsTable
        isLoading={isLoading}
        sortDirection={sortDirection}
        sortField={sortField}
        tenants={tenants}
        onSortChange={onSortChange}
        onTenantAction={onTenantAction}
      />
    </DashboardDataCard>
  );
}
