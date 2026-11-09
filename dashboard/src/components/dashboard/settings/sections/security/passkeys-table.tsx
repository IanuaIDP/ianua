'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { PasskeyActionsMenu } from '@/components/dashboard/settings/sections/security/passkey-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { Passkey } from '@/types/passkey';

type PasskeysTableProps = {
  className?: string;
  isLoading?: boolean;
  passkeys: Passkey[];
  onRemoveConfirm: (passkey: Passkey) => Promise<void> | void;
  onRenameClick: (passkey: Passkey) => void;
};

const authenticatorTypeIcons: Record<Passkey['authenticatorType'], string> = {
  cross_platform: 'usb',
  platform: 'laptop_mac',
};

export function PasskeysTable({
  className = 'mt-4',
  isLoading = false,
  passkeys,
  onRemoveConfirm,
  onRenameClick,
}: PasskeysTableProps) {
  const t = useTranslations('dashboard.settings.security');
  const columns: DashboardTableColumn<string>[] = [
    { className: 'w-[34%]', label: t('passkeys.columns.name') },
    { className: 'w-[18%]', label: t('passkeys.columns.type') },
    { className: 'w-[18%]', label: t('passkeys.columns.created') },
    { className: 'w-[20%]', label: t('passkeys.columns.lastUsed') },
  ];
  const authenticatorTypeLabels: Record<Passkey['authenticatorType'], string> = {
    cross_platform: t('passkeys.types.securityKey'),
    platform: t('passkeys.types.thisDevice'),
  };

  return (
    <DashboardTableShell
      className={className}
      columns={columns}
      emptyMessage={t('passkeys.empty')}
      hasActionsColumn
      isEmpty={passkeys.length === 0}
      isLoading={isLoading}
      loadingMessage={t('passkeys.loading')}
      minWidthClassName="min-w-150"
      onSortChange={() => {}}
    >
      {passkeys.map((passkey) => (
        <tr key={passkey.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{passkey.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <span className="inline-flex items-center gap-1.5 text-textGray">
              <span className="material-symbols-rounded text-sm!">
                {authenticatorTypeIcons[passkey.authenticatorType]}
              </span>
              {authenticatorTypeLabels[passkey.authenticatorType]}
            </span>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{passkey.created}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{passkey.lastUsed ?? t('passkeys.never')}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <PasskeyActionsMenu
              passkey={passkey}
              onRemoveConfirm={onRemoveConfirm}
              onRenameClick={onRenameClick}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
