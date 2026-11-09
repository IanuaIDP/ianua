'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TenantApiKeyActionsMenu } from '@/components/dashboard/tenant-detail/sections/api-keys/tenant-api-key-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type {
  TenantApiKey,
  TenantApiKeyAction,
  TenantApiKeySortDirection,
  TenantApiKeySortField,
} from '@/types/tenant-api-key';

type TenantApiKeysTableProps = {
  apiKeys: TenantApiKey[];
  canRevokeApiKey?: boolean;
  canUpdateApiKey?: boolean;
  isLoading?: boolean;
  onApiKeyAction: (apiKey: TenantApiKey, action: TenantApiKeyAction) => Promise<void> | void;
  onSortChange: (field: TenantApiKeySortField) => void;
  sortDirection?: TenantApiKeySortDirection;
  sortField?: TenantApiKeySortField;
};

export function TenantApiKeysTable({
  apiKeys,
  canRevokeApiKey = true,
  canUpdateApiKey = true,
  isLoading = false,
  onApiKeyAction,
  onSortChange,
  sortDirection,
  sortField,
}: TenantApiKeysTableProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const columns: DashboardTableColumn<TenantApiKeySortField>[] = [
    { className: 'w-[30%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[16%]', label: t('columns.status') },
    { className: 'w-[18%]', label: t('columns.created'), sortField: 'created_at' },
    { className: 'w-[18%]', label: t('columns.lastUsed'), sortField: 'last_used_at' },
    { className: 'w-[14%]', label: t('columns.ends') },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={apiKeys.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {apiKeys.map((apiKey) => (
        <tr key={apiKey.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{apiKey.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={apiKey.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{apiKey.created}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{apiKey.lastUsed}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{apiKey.ends ?? t('never')}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <TenantApiKeyActionsMenu
              apiKey={apiKey}
              canRevoke={canRevokeApiKey}
              canUpdate={canUpdateApiKey}
              onActionConfirm={onApiKeyAction}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
