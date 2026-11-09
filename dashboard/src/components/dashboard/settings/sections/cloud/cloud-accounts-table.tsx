'use client';

import { useTranslations } from 'next-intl';

import { CloudAccountActionsMenu } from '@/components/dashboard/settings/sections/cloud/cloud-account-actions-menu';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import { Tooltip } from '@/components/ui/tooltip';
import { getCloudProviderLabel } from '@/constants/cloud';
import type { CloudAccount, CloudAccountAction } from '@/types/cloud-account';

type CloudAccountsTableProps = {
  accounts: CloudAccount[];
  isLoading: boolean;
  onAccountAction: (account: CloudAccount, action: CloudAccountAction) => Promise<void> | void;
};

export function CloudAccountsTable({
  accounts,
  isLoading,
  onAccountAction,
}: CloudAccountsTableProps) {
  const t = useTranslations('dashboard.settings.cloud');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[24%]', label: t('columns.provider') },
    { className: 'w-[22%]', label: t('columns.account') },
    { className: 'w-[18%]', label: t('columns.status') },
    { className: 'w-[18%]', label: t('columns.connected') },
    { className: 'w-[18%]', label: t('columns.verified') },
  ];

  return (
    <DashboardTableShell
      className="rounded-b-lg"
      columns={columns}
      hasActionsColumn
      isEmpty={accounts.length === 0}
      isLoading={isLoading}
      emptyMessage={t('empty')}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-170"
      onSortChange={() => undefined}
    >
      {accounts.map((account) => (
        <tr key={account.provider} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2 font-semibold text-white">
            <TableCellText>{getCloudProviderLabel(account.provider)}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{account.account ?? t('notAvailable')}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <div className="flex items-center gap-1.5">
              <DashboardStatusBadge status={account.status} />
              {account.failureReason ? (
                <Tooltip content={account.failureReason} side="top-left">
                  <span
                    className="material-symbols-rounded text-sm! text-error"
                    aria-label={account.failureReason}
                  >
                    info
                  </span>
                </Tooltip>
              ) : null}
              {!account.revocableByYou && account.usable ? (
                <Tooltip content={t('bearerTooltip')} side="top-left">
                  <span
                    className="material-symbols-rounded text-sm! text-orange"
                    aria-label={t('bearerLabel')}
                  >
                    warning
                  </span>
                </Tooltip>
              ) : null}
            </div>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{account.connected}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{account.verified}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <CloudAccountActionsMenu account={account} onActionConfirm={onAccountAction} />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
