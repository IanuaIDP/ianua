'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantActionsMenu } from '@/components/dashboard/tenants/tenant-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import type { Tenant, TenantAction, TenantSortDirection, TenantSortField } from '@/types/tenant';
import { DashboardStatusBadge } from '../shared/dashboard-status-badge';

type TenantsTableProps = {
  isLoading?: boolean;
  onSortChange: (field: TenantSortField) => void;
  onTenantAction: (tenant: Tenant, action: TenantAction) => Promise<void> | void;
  sortDirection?: TenantSortDirection;
  sortField?: TenantSortField;
  tenants: Tenant[];
};

export function TenantsTable({
  isLoading = false,
  onSortChange,
  onTenantAction,
  sortDirection,
  sortField,
  tenants,
}: TenantsTableProps) {
  const t = useTranslations('dashboard.tenants');
  const { canManageOrganization } = useOrgAccess();
  const columns: DashboardTableColumn<TenantSortField>[] = [
    { className: 'w-[37%]', label: t('columns.name'), sortField: 'display_name' },
    { className: 'w-[26%]', label: t('columns.slug') },
    { className: 'w-[18%]', label: t('columns.status') },
    { className: 'w-[15%]', label: t('columns.created'), sortField: 'created_at' },
  ];

  return (
    <DashboardTableShell
      className="mt-4"
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn={canManageOrganization}
      isEmpty={tenants.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {tenants.map((tenant) => {
        return (
          <tr key={tenant.id} className="group h-9 transition hover:bg-hoverBg">
            <td className="px-4 py-2">
              <Link href={`/tenants/${encodeURIComponent(tenant.slug)}`}>
                <TableCellText className="font-medium text-primary underline underline-offset-2 transition hover:text-btnWithBgHover">
                  {tenant.name}
                </TableCellText>
              </Link>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{tenant.slug}</TableCellText>
            </td>
            <td className="px-4 py-2">
              <DashboardStatusBadge status={tenant.status} />
            </td>
            <td className="px-4 py-2">
              <TableCellText>{tenant.created}</TableCellText>
            </td>
            {canManageOrganization ? (
              <DashboardTableActionsCell>
                <TenantActionsMenu tenant={tenant} onActionConfirm={onTenantAction} />
              </DashboardTableActionsCell>
            ) : null}
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
