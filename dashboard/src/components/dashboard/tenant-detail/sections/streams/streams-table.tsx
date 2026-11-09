'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { StreamActionsMenu } from '@/components/dashboard/tenant-detail/sections/streams/stream-actions-menu';
import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { TableCellText } from '@/components/ui/table-cell';
import { useStreamOptions } from '@/hooks/dashboard/use-stream-options';
import type { Stream, StreamAction } from '@/types/stream';
import { cn } from '@/utils/cn';

const VISIBLE_SIGNAL_TYPES = 2;

type StreamsTableProps = {
  canDeleteStream?: boolean;
  canUpdateStream?: boolean;
  isLoading?: boolean;
  onEditClick: (stream: Stream) => void;
  onRowClick?: (stream: Stream) => void;
  onStreamAction: (stream: Stream, action: StreamAction) => Promise<void> | void;
  streams: Stream[];
};

export function StreamsTable({
  canDeleteStream = true,
  canUpdateStream = true,
  isLoading = false,
  onEditClick,
  onRowClick,
  onStreamAction,
  streams,
}: StreamsTableProps) {
  const t = useTranslations('dashboard.streams');
  const { deliveryMethodLabel, signalTypeLabel } = useStreamOptions();
  const copy = useCopyToClipboard();
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[26%]', label: t('columns.endpoint') },
    { className: 'w-[13%]', label: t('columns.deliveryMethod') },
    { className: 'w-[31%]', label: t('columns.signalTypes') },
    { className: 'w-[12%]', label: t('columns.status') },
    { className: 'w-[13%]', label: t('columns.created') },
  ];

  async function copyEndpoint(endpoint: string) {
    await copy(endpoint, t('endpointCopied'));
  }

  return (
    <DashboardTableShell
      className="mt-4"
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn
      isEmpty={streams.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {streams.map((stream) => {
        const visibleSignalTypes = stream.signalTypes.slice(0, VISIBLE_SIGNAL_TYPES);
        const hiddenSignalTypesCount = stream.signalTypes.length - visibleSignalTypes.length;

        return (
          <tr
            key={stream.id}
            className={cn('group h-11 transition hover:bg-hoverBg', onRowClick && 'cursor-pointer')}
            onClick={() => onRowClick?.(stream)}
          >
            <td className="px-4 py-2">
              <div className="flex min-w-0 items-center gap-1.5">
                <TableCellText className="font-semibold text-white" tooltip={stream.endpoint}>
                  {stream.endpoint}
                </TableCellText>
                <button
                  type="button"
                  aria-label={t('copyEndpoint')}
                  onClick={(event) => {
                    event.stopPropagation();
                    void copyEndpoint(stream.endpoint);
                  }}
                  className="flex size-5 shrink-0 items-center justify-center rounded text-textGray transition hover:text-white"
                >
                  <span className="material-symbols-rounded text-base!" aria-hidden>
                    content_copy
                  </span>
                </button>
              </div>
            </td>
            <td className="px-4 py-2">
              <span className="inline-flex h-5 items-center rounded-md bg-white/15 px-1.5 text-[10px] font-medium leading-none text-white">
                {deliveryMethodLabel(stream.deliveryMethod)}
              </span>
            </td>
            <td className="px-4 py-2">
              <div className="flex flex-wrap items-center gap-1">
                {stream.signalTypes.length === 0 ? (
                  <span className="inline-flex items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white">
                    {t('allTypes')}
                  </span>
                ) : (
                  <>
                    {visibleSignalTypes.map((signalType) => (
                      <span
                        key={signalType}
                        className="inline-flex items-center rounded-md px-1.5 py-0.5 bg-surfaceChip text-[10px] font-medium leading-none text-white"
                      >
                        {signalTypeLabel(signalType)}
                      </span>
                    ))}
                    {hiddenSignalTypesCount > 0 ? (
                      <FloatingTooltip
                        title={t('columns.signalTypes')}
                        content={
                          <div className="flex max-w-64 flex-wrap gap-1">
                            {stream.signalTypes.map((signalType) => (
                              <span
                                key={signalType}
                                className="inline-flex h-5 items-center rounded-md bg-surfaceChip px-1.5 text-[10px] font-medium leading-none text-white"
                              >
                                {signalTypeLabel(signalType)}
                              </span>
                            ))}
                          </div>
                        }
                      >
                        <span className="inline-flex items-center rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium leading-none text-white hover:bg-white/15">
                          +{hiddenSignalTypesCount}
                        </span>
                      </FloatingTooltip>
                    ) : null}
                  </>
                )}
              </div>
            </td>
            <td className="px-4 py-2">
              <div className="flex items-center gap-1.5">
                <DashboardStatusBadge status={stream.status} />
                {stream.consecutiveFailures > 0 ? (
                  <FloatingTooltip content={t('failures', { count: stream.consecutiveFailures })}>
                    <span className="material-symbols-rounded text-sm! text-orange" aria-hidden>
                      warning
                    </span>
                  </FloatingTooltip>
                ) : null}
              </div>
            </td>
            <td className="px-4 py-2">
              <TableCellText>{stream.created}</TableCellText>
            </td>
            <DashboardTableActionsCell>
              <StreamActionsMenu
                canDelete={canDeleteStream}
                canUpdate={canUpdateStream}
                stream={stream}
                onActionConfirm={onStreamAction}
                onEditClick={onEditClick}
              />
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
