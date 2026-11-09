'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ApiKeyActionsMenu } from '@/components/dashboard/settings/sections/api-keys/api-key-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { ApiKey, ApiKeyAction, ApiKeySortDirection, ApiKeySortField } from '@/types/api-key';

type ApiKeysTableProps = {
  apiKeys: ApiKey[];
  isLoading: boolean;
  onApiKeyAction: (apiKey: ApiKey, action: ApiKeyAction) => Promise<void> | void;
  onSortChange: (field: ApiKeySortField) => void;
  sortDirection?: ApiKeySortDirection;
  sortField?: ApiKeySortField;
};

export function ApiKeysTable({
  apiKeys,
  isLoading,
  onApiKeyAction,
  onSortChange,
  sortDirection,
  sortField,
}: ApiKeysTableProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const columns: DashboardTableColumn<ApiKeySortField>[] = [
    { className: 'w-[22%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[22%]', label: t('columns.key') },
    { className: 'w-[18%]', label: t('columns.status') },
    { className: 'w-[18%]', label: t('columns.created'), sortField: 'created_at' },
    { className: 'w-[16%]', label: t('columns.lastUsed'), sortField: 'last_used_at' },
  ];

  return (
    <DashboardTableShell
      className="rounded-b-lg"
      columns={columns}
      hasActionsColumn
      isEmpty={apiKeys.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-170"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {apiKeys.map((apiKey) => (
        <tr key={apiKey.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2 font-semibold text-white">
            <TableCellText>{apiKey.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText className="inline-block rounded-md bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-white">
              {apiKey.key}
            </TableCellText>
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
          <DashboardTableActionsCell>
            <ApiKeyActionsMenu apiKey={apiKey} onActionConfirm={onApiKeyAction} />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
