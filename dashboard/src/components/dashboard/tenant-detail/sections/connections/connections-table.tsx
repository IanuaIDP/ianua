'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ConnectionActionsMenu } from '@/components/dashboard/tenant-detail/sections/connections/connection-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type {
  Connection,
  ConnectionAction,
  ConnectionSortDirection,
  ConnectionSortField,
} from '@/types/connection';

type ConnectionsTableProps = {
  canDeleteConnection?: boolean;
  canUpdateConnection?: boolean;
  connections: Connection[];
  isLoading?: boolean;
  onConnectionAction: (connection: Connection, action: ConnectionAction) => Promise<void> | void;
  onDeleteClick: (connection: Connection) => void;
  onSortChange: (field: ConnectionSortField) => void;
  sortDirection?: ConnectionSortDirection;
  sortField?: ConnectionSortField;
};

export function ConnectionsTable({
  canDeleteConnection = true,
  canUpdateConnection = true,
  connections,
  isLoading = false,
  onConnectionAction,
  onDeleteClick,
  onSortChange,
  sortDirection,
  sortField,
}: ConnectionsTableProps) {
  const t = useTranslations('dashboard.connections');
  const tStatus = useTranslations('dashboard.status');
  const columns: DashboardTableColumn<ConnectionSortField>[] = [
    { className: 'w-[30%]', label: t('columns.name'), sortField: 'provider_name' },
    { className: 'w-[18%]', label: t('columns.protocol') },
    { className: 'w-[16%]', label: t('columns.jit') },
    { className: 'w-[16%]', label: t('columns.status'), sortField: 'status' },
    { className: 'w-[20%]', label: t('columns.created'), sortField: 'created_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={connections.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {connections.map((connection) => (
        <tr key={connection.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{connection.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <span className="inline-flex h-5 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
              {connection.protocol}
            </span>
          </td>
          <td className="px-4 py-2">
            <TableCellText>
              {connection.isJitProvisioningEnabled ? tStatus('Enabled') : tStatus('Disabled')}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={connection.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{connection.created}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <ConnectionActionsMenu
              canDelete={canDeleteConnection}
              canUpdate={canUpdateConnection}
              connection={connection}
              onActionConfirm={onConnectionAction}
              onDeleteClick={onDeleteClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
