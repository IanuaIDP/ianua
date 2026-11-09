'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { DeviceActionsMenu } from '@/components/dashboard/settings/sections/security/device-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { TrustedDevice } from '@/types/device';

type TrustedDevicesTableProps = {
  className?: string;
  devices: TrustedDevice[];
  isLoading?: boolean;
  onRevokeConfirm: (device: TrustedDevice) => Promise<void> | void;
};

export function TrustedDevicesTable({
  className = 'mt-4',
  devices,
  isLoading = false,
  onRevokeConfirm,
}: TrustedDevicesTableProps) {
  const t = useTranslations('dashboard.settings.security');
  const columns: DashboardTableColumn<string>[] = [
    { className: 'w-[46%]', label: t('devices.columns.device') },
    { className: 'w-[22%]', label: t('devices.columns.status') },
    { className: 'w-[22%]', label: t('devices.columns.added') },
  ];

  return (
    <DashboardTableShell
      className={className}
      columns={columns}
      emptyMessage={t('devices.empty')}
      hasActionsColumn
      isEmpty={devices.length === 0}
      isLoading={isLoading}
      loadingMessage={t('devices.loading')}
      minWidthClassName="min-w-150"
      onSortChange={() => {}}
    >
      {devices.map((device) => (
        <tr key={device.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <span className="inline-flex items-center gap-1.5 font-semibold text-white">
              <span className="material-symbols-rounded text-sm! text-textGray">devices</span>
              {device.name}
            </span>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={device.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{device.created}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            {device.status === 'Trusted' ? (
              <DeviceActionsMenu device={device} onRevokeConfirm={onRevokeConfirm} />
            ) : null}
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
