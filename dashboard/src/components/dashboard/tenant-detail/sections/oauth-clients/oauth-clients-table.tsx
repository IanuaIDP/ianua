'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { OAuthClientActionsMenu } from '@/components/dashboard/tenant-detail/sections/oauth-clients/oauth-client-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type {
  OAuthClient,
  OAuthClientAction,
  OAuthClientSortDirection,
  OAuthClientSortField,
} from '@/types/oauth-client';

type OAuthClientsTableProps = {
  canRevokeClient?: boolean;
  canUpdateClient?: boolean;
  clients: OAuthClient[];
  isLoading?: boolean;
  onClientAction: (client: OAuthClient, action: OAuthClientAction) => Promise<void> | void;
  onEditClick: (client: OAuthClient) => void;
  onSortChange: (field: OAuthClientSortField) => void;
  sortDirection?: OAuthClientSortDirection;
  sortField?: OAuthClientSortField;
};

export function OAuthClientsTable({
  canRevokeClient = true,
  canUpdateClient = true,
  clients,
  isLoading = false,
  onClientAction,
  onEditClick,
  onSortChange,
  sortDirection,
  sortField,
}: OAuthClientsTableProps) {
  const t = useTranslations('dashboard.oauthClients');
  const columns: DashboardTableColumn<OAuthClientSortField>[] = [
    { className: 'w-[40%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[25%]', label: t('columns.status'), sortField: 'status' },
    { className: 'w-[35%]', label: t('columns.created'), sortField: 'created_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={clients.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {clients.map((client) => (
        <tr key={client.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{client.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={client.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{client.created}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <OAuthClientActionsMenu
              canRevoke={canRevokeClient}
              canUpdate={canUpdateClient}
              client={client}
              onActionConfirm={onClientAction}
              onEditClick={onEditClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
