'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import { useStreamOptions } from '@/hooks/dashboard/use-stream-options';
import type { StreamDelivery } from '@/types/stream';

type StreamDeliveriesTableProps = {
  deliveries: StreamDelivery[];
  isLoading?: boolean;
};

export function StreamDeliveriesTable({
  deliveries,
  isLoading = false,
}: StreamDeliveriesTableProps) {
  const t = useTranslations('dashboard.streams.deliveries');
  const { signalTypeLabel } = useStreamOptions();
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[40%]', label: t('signalType') },
    { className: 'w-[25%]', label: t('outcome') },
    { className: 'w-[35%]', label: t('dateTime') },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      emptyMessage={t('empty')}
      isEmpty={deliveries.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-160"
      onSortChange={() => {}}
    >
      {deliveries.map((delivery) => (
        <tr key={delivery.id} className="h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="text-white">
              {signalTypeLabel(delivery.signalType)}
            </TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={delivery.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{delivery.attemptedAt}</TableCellText>
          </td>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
