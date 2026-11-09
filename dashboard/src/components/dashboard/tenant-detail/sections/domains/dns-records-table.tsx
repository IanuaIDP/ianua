'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { DnsRecordActionsMenu } from '@/components/dashboard/tenant-detail/sections/domains/dns-record-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { DnsRecord } from '@/types/dns-record';
import { formatDnsRecordValueForDisplay } from '@/utils/dns-record';

type DnsRecordsTableProps = {
  canUpdate?: boolean;
  isLoading?: boolean;
  records: DnsRecord[];
  onDelete: (record: DnsRecord) => void;
  onEdit: (record: DnsRecord) => void;
};

const managedBadgeClassName =
  'inline-flex h-5 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white';

export function DnsRecordsTable({
  canUpdate = true,
  isLoading = false,
  records,
  onDelete,
  onEdit,
}: DnsRecordsTableProps) {
  const t = useTranslations('dashboard.domains.dns');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[24%]', label: t('columns.name') },
    { className: 'w-[10%]', label: t('columns.type') },
    { className: 'w-[38%]', label: t('columns.values') },
    { className: 'w-[10%]', label: t('columns.ttl') },
    { className: 'w-[18%]', label: t('columns.managed') },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn
      isEmpty={records.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-210"
      onSortChange={() => {}}
    >
      {records.map((record) => {
        const canEditRow = canUpdate && !record.isManagedByIanua;

        return (
          <tr
            key={`${record.name}-${record.recordType}`}
            className="group h-11 transition hover:bg-hoverBg"
          >
            <td className="px-4 py-2">
              <TableCellText className="font-semibold text-white">{record.name}</TableCellText>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{record.recordType}</TableCellText>
            </td>
            <td className="px-4 py-2">
              <TableCellText
                tooltip={record.values
                  .map((value) => formatDnsRecordValueForDisplay(record.recordType, value))
                  .join(', ')}
              >
                {record.values
                  .map((value) => formatDnsRecordValueForDisplay(record.recordType, value))
                  .join(', ')}
              </TableCellText>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{t('ttl', { seconds: record.ttlSeconds })}</TableCellText>
            </td>
            <td className="px-4 py-2">
              {record.isManagedByIanua ? (
                <span className={managedBadgeClassName}>{t('managedByIanua')}</span>
              ) : (
                <TableCellText className="text-textGray">—</TableCellText>
              )}
            </td>
            <DashboardTableActionsCell>
              <DnsRecordActionsMenu
                canEdit={canEditRow}
                record={record}
                onDelete={onDelete}
                onEdit={onEdit}
              />
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
