'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { CryptoKeyActionsMenu } from '@/components/dashboard/tenant-detail/sections/crypto/crypto-key-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import type { CryptoKey, CryptoKeyAction } from '@/types/crypto';

type CryptoKeysTableProps = {
  canRevokeKey?: boolean;
  cryptoKeys: CryptoKey[];
  isLoading?: boolean;
  onKeyAction: (cryptoKey: CryptoKey, action: CryptoKeyAction) => Promise<void> | void;
};

export function CryptoKeysTable({
  canRevokeKey = true,
  cryptoKeys,
  isLoading = false,
  onKeyAction,
}: CryptoKeysTableProps) {
  const t = useTranslations('dashboard.crypto');
  const columns: DashboardTableColumn<string>[] = [
    { className: 'w-[40%]', label: t('keys.columns.keyId') },
    { className: 'w-[15%]', label: t('keys.columns.algorithm') },
    { className: 'w-[13%]', label: t('keys.columns.status') },
    { className: 'w-[16%]', label: t('keys.columns.created') },
    { className: 'w-[16%]', label: t('keys.columns.expires') },
  ];
  const copy = useCopyToClipboard();
  const activeKeyCount = cryptoKeys.filter((cryptoKey) => cryptoKey.status === 'Active').length;

  async function copyKeyId(keyId: string) {
    await copy(keyId, t('keyIdCopied'));
  }

  return (
    <DashboardTableShell
      columns={columns}
      hasActionsColumn
      isEmpty={cryptoKeys.length === 0}
      isLoading={isLoading}
      loadingMessage={t('keys.loading')}
      minWidthClassName="min-w-180"
      onSortChange={() => undefined}
    >
      {cryptoKeys.map((cryptoKey) => (
        <tr key={cryptoKey.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <div className="flex min-w-0 items-center gap-2">
              <TableCellText className="font-semibold text-white">{cryptoKey.id}</TableCellText>
              <button
                type="button"
                aria-label={t('copyKeyId')}
                onClick={() => void copyKeyId(cryptoKey.id)}
                className="flex size-5 shrink-0 items-center justify-center rounded text-textGray transition hover:text-white"
              >
                <span className="material-symbols-rounded text-base!" aria-hidden="true">
                  content_copy
                </span>
              </button>
            </div>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{cryptoKey.algorithm}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={cryptoKey.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{cryptoKey.created}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{cryptoKey.expires}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <CryptoKeyActionsMenu
              canRevoke={canRevokeKey && (cryptoKey.status !== 'Active' || activeKeyCount > 1)}
              cryptoKey={cryptoKey}
              onActionConfirm={onKeyAction}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
