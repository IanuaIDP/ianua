'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import type { CryptoJwksKey } from '@/types/crypto';

type CryptoJwksTableProps = {
  isLoading?: boolean;
  keys: CryptoJwksKey[];
};

export function CryptoJwksTable({ isLoading = false, keys }: CryptoJwksTableProps) {
  const t = useTranslations('dashboard.crypto');
  const columns: DashboardTableColumn<string>[] = [
    { className: 'w-[46%]', label: t('jwks.columns.keyId') },
    { className: 'w-[18%]', label: t('jwks.columns.algorithm') },
    { className: 'w-[18%]', label: t('jwks.columns.keyType') },
    { className: 'w-[18%]', label: t('jwks.columns.curve') },
  ];
  const copy = useCopyToClipboard();

  async function copyKeyId(keyId: string) {
    await copy(keyId, t('keyIdCopied'));
  }

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={keys.length === 0}
      isLoading={isLoading}
      loadingMessage={t('jwks.loading')}
      minWidthClassName="min-w-150"
      onSortChange={() => undefined}
    >
      {keys.map((key) => (
        <tr key={key.id} className="h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <div className="flex min-w-0 items-center gap-2">
              <TableCellText className="font-semibold text-white">{key.id}</TableCellText>
              <button
                type="button"
                aria-label={t('copyKeyId')}
                onClick={() => void copyKeyId(key.id)}
                className="flex size-5 shrink-0 items-center justify-center rounded text-textGray transition hover:text-white"
              >
                <span className="material-symbols-rounded text-base!" aria-hidden="true">
                  content_copy
                </span>
              </button>
            </div>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{key.algorithm}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{key.keyType}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{key.curve}</TableCellText>
          </td>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
