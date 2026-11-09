'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { GroupActionsMenu } from '@/components/dashboard/tenant-detail/sections/groups/group-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { Group, GroupSortDirection, GroupSortField } from '@/types/group';

type GroupsTableProps = {
  canDeleteGroup?: boolean;
  canUpdateGroup?: boolean;
  groups: Group[];
  isLoading?: boolean;
  onDeleteClick: (group: Group) => void;
  onEditClick: (group: Group) => void;
  onMembersClick: (group: Group) => void;
  onRolesClick: (group: Group) => void;
  onSortChange: (field: GroupSortField) => void;
  sortDirection?: GroupSortDirection;
  sortField?: GroupSortField;
};

export function GroupsTable({
  canDeleteGroup = true,
  canUpdateGroup = true,
  groups,
  isLoading = false,
  onDeleteClick,
  onEditClick,
  onMembersClick,
  onRolesClick,
  onSortChange,
  sortDirection,
  sortField,
}: GroupsTableProps) {
  const t = useTranslations('dashboard.groups');
  const columns: DashboardTableColumn<GroupSortField>[] = [
    { className: 'w-[32%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[26%]', label: t('columns.parent') },
    { className: 'w-[18%]', label: t('columns.roles') },
    { className: 'w-[24%]', label: t('columns.created'), sortField: 'created_at' },
  ];
  const nameById = new Map(groups.map((group) => [group.id, group.name]));

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={groups.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      emptyMessage={t('empty')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {groups.map((group) => (
        <tr key={group.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{group.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>
              {group.parentId ? (nameById.get(group.parentId) ?? t('anotherGroup')) : '—'}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{group.rolesCount}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{group.createdAt}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <GroupActionsMenu
              canDelete={canDeleteGroup}
              canUpdate={canUpdateGroup}
              group={group}
              onDeleteClick={onDeleteClick}
              onEditClick={onEditClick}
              onMembersClick={onMembersClick}
              onRolesClick={onRolesClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
