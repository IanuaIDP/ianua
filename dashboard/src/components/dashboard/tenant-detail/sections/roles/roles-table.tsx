'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { RoleActionsMenu } from '@/components/dashboard/tenant-detail/sections/roles/role-actions-menu';
import { RolePermissionsCell } from '@/components/dashboard/tenant-detail/sections/roles/role-permissions-cell';
import { TableCellText } from '@/components/ui/table-cell';
import type { Role, RoleSortDirection, RoleSortField } from '@/types/role';

type RolesTableProps = {
  canDeleteRole?: boolean;
  canUpdateRole?: boolean;
  isLoading?: boolean;
  onDeleteClick: (role: Role) => void;
  onEditClick: (role: Role) => void;
  onSortChange: (field: RoleSortField) => void;
  roles: Role[];
  sortDirection?: RoleSortDirection;
  sortField?: RoleSortField;
};

export function RolesTable({
  canDeleteRole = true,
  canUpdateRole = true,
  isLoading = false,
  onDeleteClick,
  onEditClick,
  onSortChange,
  roles,
  sortDirection,
  sortField,
}: RolesTableProps) {
  const t = useTranslations('dashboard.tenantRoles');
  const columns: DashboardTableColumn<RoleSortField>[] = [
    { className: 'w-[27%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[33%]', label: t('columns.permissions') },
    { className: 'w-[16%]', label: t('columns.users') },
    { className: 'w-[24%]', label: t('columns.created'), sortField: 'created_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={roles.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {roles.map((role) => (
        <tr key={role.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <div className="flex items-center gap-2">
              <TableCellText className="font-semibold text-white">{role.name}</TableCellText>
              {role.isDefault && (
                <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
                  {t('default')}
                </span>
              )}
            </div>
          </td>
          <td className="px-4 py-2">
            <RolePermissionsCell role={role} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{role.assignedUserCount}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{role.createdAt}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <RoleActionsMenu
              canDelete={canDeleteRole}
              canUpdate={canUpdateRole}
              role={role}
              onDeleteClick={onDeleteClick}
              onEditClick={onEditClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
