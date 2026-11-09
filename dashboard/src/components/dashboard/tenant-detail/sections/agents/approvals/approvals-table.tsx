'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ApprovalActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/approvals/approval-actions-menu';
import type { Approval } from '@/types/approval';
import { formatBackendDateTime, formatCountdown, parseBackendTimestamp } from '@/utils/date';

type ApprovalsTableProps = {
  approvals: Approval[];
  canReview: boolean;
  isLoading?: boolean;
  runsHref: string;
  onApprove: (approval: Approval) => Promise<void> | void;
  onDeny: (approval: Approval) => Promise<void> | void;
};

const chipClassName =
  'inline-flex items-center gap-1 rounded-md bg-surfaceChip px-1.5 py-0.5 text-[10px] font-medium text-white';

function getRunDisplaySuffix(runId: string) {
  return `run-${runId.slice(-4)}`;
}

function getStatusTimeLabel(
  approval: Approval,
  labels: Record<'approvedAt' | 'deniedAt' | 'expiredAt' | 'expiresIn', string>,
): { label: string; value: string } | null {
  if (approval.status === 'AwaitingApproval') {
    const expiresAt = parseBackendTimestamp(approval.expiresAt);

    return expiresAt ? { label: labels.expiresIn, value: formatCountdown(expiresAt) } : null;
  }

  if (!approval.decidedAt) {
    return null;
  }

  const label =
    approval.status === 'Approved'
      ? labels.approvedAt
      : approval.status === 'Denied'
        ? labels.deniedAt
        : labels.expiredAt;

  return { label, value: formatBackendDateTime(approval.decidedAt) };
}

export function ApprovalsTable({
  approvals,
  canReview,
  isLoading = false,
  runsHref,
  onApprove,
  onDeny,
}: ApprovalsTableProps) {
  const t = useTranslations('dashboard.agents.approvals.table');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('title') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={approvals.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {approvals.map((approval) => {
        const statusTime = getStatusTimeLabel(approval, {
          approvedAt: t('approvedAt'),
          deniedAt: t('deniedAt'),
          expiredAt: t('expiredAt'),
          expiresIn: t('expiresIn'),
        });

        return (
          <tr key={approval.id} className="group transition hover:bg-hoverBg">
            <td className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-white">{approval.action}</span>
                {approval.purpose ? (
                  <span className={chipClassName}>{approval.purpose}</span>
                ) : null}
                {approval.pendingTool ? (
                  <span className={chipClassName}>{approval.pendingTool}</span>
                ) : null}
                {approval.approversNeeded > 1 ? (
                  <span className={chipClassName}>{t('twoPeople')}</span>
                ) : null}
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-textGray">
                {approval.runId ? (
                  <Link
                    href={`${runsHref}?runId=${encodeURIComponent(approval.runId)}`}
                    className={chipClassName}
                  >
                    <span className="material-symbols-rounded text-sm!" aria-hidden>
                      play_circle
                    </span>
                    {getRunDisplaySuffix(approval.runId)}
                  </Link>
                ) : null}
                <span className="flex items-center gap-1.5">
                  {t('delegation')}{' '}
                  <span className={chipClassName}>{approval.delegationId.slice(0, 8) || '—'}</span>
                </span>
                {approval.requestedBy ? (
                  <span>{t('requestedBy', { name: approval.requestedBy })}</span>
                ) : null}
                {approval.firstApprovedBy ? (
                  <span>{t('firstApprovedBy', { name: approval.firstApprovedBy })}</span>
                ) : null}
                {statusTime ? (
                  <>
                    <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                    <span>
                      {statusTime.label} <span className="text-white">{statusTime.value}</span>
                    </span>
                  </>
                ) : null}
              </div>
            </td>
            <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
              <div className="flex items-center justify-end gap-3">
                <DashboardStatusBadge status={approval.status} />
                {approval.status === 'AwaitingApproval' && canReview ? (
                  <ApprovalActionsMenu approval={approval} onApprove={onApprove} onDeny={onDeny} />
                ) : null}
              </div>
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
