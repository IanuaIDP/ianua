'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ResourceTypeActionsMenu } from '@/components/dashboard/tenant-detail/sections/roles/resource-type-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type {
  ResourceType,
  ResourceTypeSortDirection,
  ResourceTypeSortField,
} from '@/types/resource-type';

type ResourceTypesTableProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  isLoading?: boolean;
  onDeleteClick: (resourceType: ResourceType) => void;
  onEditClick: (resourceType: ResourceType) => void;
  onSortChange: (field: ResourceTypeSortField) => void;
  resourceTypes: ResourceType[];
  sortDirection?: ResourceTypeSortDirection;
  sortField?: ResourceTypeSortField;
};

export function ResourceTypesTable({
  canDelete = true,
  canUpdate = true,
  isLoading = false,
  onDeleteClick,
  onEditClick,
  onSortChange,
  resourceTypes,
  sortDirection,
  sortField,
}: ResourceTypesTableProps) {
  const t = useTranslations('dashboard.resources');
  const columns: DashboardTableColumn<ResourceTypeSortField>[] = [
    { className: 'w-[24%]', label: t('columns.resource'), sortField: 'key' },
    { className: 'w-[40%]', label: t('columns.actions') },
    { className: 'w-[36%]', label: t('columns.created'), sortField: 'created_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={resourceTypes.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {resourceTypes.map((resourceType) => (
        <tr key={resourceType.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <div className="flex items-center gap-2">
              <TableCellText className="font-semibold text-white">
                {resourceType.displayName}
              </TableCellText>
              <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
                {resourceType.key}
              </span>
            </div>
          </td>
          <td className="px-4 py-2">
            <div className="flex flex-wrap gap-1.5">
              {resourceType.actions.map((action) => (
                <span
                  key={action.key}
                  title={t('grants', { list: action.grants.join(', ') })}
                  className="rounded-full bg-surfaceRaised px-2.5 py-1 text-xs font-medium text-textGray"
                >
                  {action.displayName}
                  {action.grants.length > 1 ? (
                    <span className="ml-1 text-focus">+{action.grants.length - 1}</span>
                  ) : null}
                </span>
              ))}
            </div>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{resourceType.created}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <ResourceTypeActionsMenu
              canDelete={canDelete}
              canUpdate={canUpdate}
              resourceType={resourceType}
              onDeleteClick={onDeleteClick}
              onEditClick={onEditClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
