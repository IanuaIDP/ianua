'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { FlowActionsMenu } from '@/components/dashboard/tenant-detail/sections/flows/flow-actions-menu';
import type { Flow, FlowAction } from '@/types/flow';
import { cn } from '@/utils/cn';
import { formatBackendDateTime } from '@/utils/date';
import { getFlowNodeCounts, getFlowStageDisplay, getFlowStageProgress } from '@/utils/flow';

type FlowsTableProps = {
  canCancel: boolean;
  canDelete: boolean;
  flows: Flow[];
  isLoading?: boolean;
  onFlowAction: (flow: Flow, action: FlowAction) => Promise<void> | void;
  onFlowClick?: (flow: Flow) => void;
};

export function FlowsTable({
  canCancel,
  canDelete,
  flows,
  isLoading = false,
  onFlowAction,
  onFlowClick,
}: FlowsTableProps) {
  const t = useTranslations('dashboard.flows');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('title') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={flows.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {flows.map((flow) => {
        const { settled, total } = getFlowNodeCounts(flow);
        const stage = getFlowStageDisplay(flow);
        const progress = getFlowStageProgress(flow);

        return (
          <tr
            key={flow.id}
            className={cn('group transition hover:bg-hoverBg', onFlowClick && 'cursor-pointer')}
            onClick={() => onFlowClick?.(flow)}
          >
            <td className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-white">{flow.name}</span>
                <span className="inline-flex h-6 items-center rounded-full px-2.5 text-[10px] border border-borderGray font-medium text-textGray bg-surfaceChip">
                  <span
                    className={cn('font-semibold text-white', settled > 0 ? 'text-primary' : '')}
                  >
                    {settled}/{total}
                  </span>
                  &nbsp;{t('nodesSettled')}
                </span>
              </div>
              {flow.description ? (
                <p className="mt-1 text-[10px] text-textGray">{flow.description}</p>
              ) : null}
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-textGray">
                <span>
                  {t('id')} <span className="text-white">{flow.id.slice(0, 8)}</span>
                </span>
                <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                <span>
                  {t('created')}{' '}
                  <span className="text-white">{formatBackendDateTime(flow.createdAt)}</span>
                </span>
                <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                <span className="flex items-center gap-2">
                  <span className="inline-flex h-5 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white">
                    {t('stage', { current: stage.current, total: stage.total })}
                  </span>
                  <span className="h-1.5 w-30 overflow-hidden rounded-full bg-white/15" aria-hidden>
                    <span
                      className="block h-full rounded-full bg-primary"
                      style={{ width: `${progress}%` }}
                    />
                  </span>
                </span>
              </div>
            </td>
            <DashboardTableActionsCell className="px-4 py-2.5">
              <div className="flex items-center justify-end gap-3">
                <DashboardStatusBadge status={flow.status} />
                <FlowActionsMenu
                  canCancel={canCancel}
                  canDelete={canDelete}
                  flow={flow}
                  onActionConfirm={onFlowAction}
                />
              </div>
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
