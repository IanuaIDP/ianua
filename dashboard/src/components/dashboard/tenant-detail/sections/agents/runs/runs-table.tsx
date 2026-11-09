'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { RunActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/runs/run-actions-menu';
import type { ModelProvider } from '@/types/model-provider';
import type { RunSummary } from '@/types/run';
import { getRunDisplayId } from '@/utils/run';

type RunsTableProps = {
  approvalsHref: string;
  canReviewApproval: boolean;
  canStop: boolean;
  canView: boolean;
  isLoading?: boolean;
  providers: ModelProvider[];
  runs: RunSummary[];
  onStopRun: (run: RunSummary) => Promise<void> | void;
  onViewTrace: (run: RunSummary) => void;
};

const chipClassName =
  'inline-flex items-center gap-1 rounded-full bg-surfaceChip px-2.5 py-1 text-[10px] font-medium text-white';

export function RunsTable({
  approvalsHref,
  canReviewApproval,
  canStop,
  canView,
  isLoading = false,
  providers,
  runs,
  onStopRun,
  onViewTrace,
}: RunsTableProps) {
  const t = useTranslations('dashboard.agents.runs');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('title') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={runs.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {runs.map((run) => {
        const provider = providers.find((candidate) => candidate.id === run.providerId);

        return (
          <tr key={run.id} className="group transition hover:bg-hoverBg">
            <td className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold text-white">{getRunDisplayId(run)}</span>
                {provider ? (
                  <span className={chipClassName}>
                    <span
                      className="material-symbols-rounded text-sm! text-textGray mt-px"
                      aria-hidden
                    >
                      neurology
                    </span>
                    {provider.model}
                  </span>
                ) : null}
              </div>
              <p className="mt-1.5 line-clamp-2 text-xs text-textGray">{run.goal}</p>
              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                {run.purpose.map((purpose) => (
                  <span key={purpose} className={chipClassName}>
                    {purpose}
                  </span>
                ))}
                {typeof run.maxSteps === 'number' ? (
                  <>
                    <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                    <span className="text-[10px] text-textGray">{t('stepLimit')}</span>
                    <span className={chipClassName}>{run.maxSteps}</span>
                  </>
                ) : null}
              </div>
            </td>
            <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
              <div className="flex items-center justify-end gap-3">
                {run.exposure !== 'Public' ? <DashboardStatusBadge status={run.exposure} /> : null}
                <DashboardStatusBadge status={run.status} />
                {run.status === 'AwaitingApproval' && canReviewApproval ? (
                  <Link
                    href={`${approvalsHref}?runId=${encodeURIComponent(run.id)}`}
                    className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-borderGray bg-cardBg px-2.5 text-[10px] font-semibold text-white transition hover:bg-hoverBg"
                  >
                    <span className="material-symbols-rounded text-sm!" aria-hidden>
                      assignment_turned_in
                    </span>
                    {t('reviewApproval')}
                  </Link>
                ) : null}
                <RunActionsMenu
                  canStop={canStop}
                  canView={canView}
                  run={run}
                  onStopRun={onStopRun}
                  onViewTrace={onViewTrace}
                />
              </div>
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
