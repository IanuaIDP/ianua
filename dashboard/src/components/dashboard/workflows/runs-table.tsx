'use client';

import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';

import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import { ExposureBadge, RunStatusBadge } from '@/components/dashboard/workflows/workflow-badges';
import { useWorkflowCaller } from '@/hooks/dashboard/use-workflow-caller';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { Execution } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { formatBackendDateTime } from '@/utils/date';
import { getActorWord } from '@/utils/workflow-actor';

type RunsTableProps = {
  emptyMessage: string;
  isLoading: boolean;
  /** The workflow each id belongs to, when the table lists more than one workflow. */
  namesByWorkflow?: Map<string, string>;
  runs: Execution[];
};

/** One line per run: when, what started it, who it acted for, how it ended. */
export function RunsTable({ emptyMessage, isLoading, namesByWorkflow, runs }: RunsTableProps) {
  const t = useTranslations('dashboard.workflows.runs');
  const tCause = useLooseTranslations('dashboard.workflows.cause');
  const tActor = useTranslations('dashboard.workflows.actor');
  const router = useRouter();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const caller = useWorkflowCaller();
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[24%]', label: t('columns.when') },
    ...(namesByWorkflow ? [{ className: 'w-[26%]', label: t('columns.workflow') }] : []),
    { className: 'w-[18%]', label: t('columns.cause') },
    { className: 'w-[14%]', label: t('columns.actingFor') },
    { className: 'w-[18%]', label: t('columns.status') },
  ];

  function openRun(run: Execution) {
    router.push(
      getTenantScopedPath(
        isTenantView,
        orgSlug,
        tenantSlug,
        `workflows/runs/${run.id}`,
        `workflows/runs/${run.id}`,
      ),
    );
  }

  return (
    <DashboardTableShell
      columns={columns}
      emptyMessage={emptyMessage}
      isEmpty={runs.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={() => {}}
    >
      {runs.map((run) => (
        <tr
          key={run.id}
          className="group h-11 cursor-pointer transition hover:bg-hoverBg"
          onClick={() => openRun(run)}
        >
          <td className="px-4 py-2">
            <TableCellText className="text-white">
              {formatBackendDateTime(run.createdAt)}
            </TableCellText>
          </td>
          {namesByWorkflow ? (
            <td className="px-4 py-2">
              <TableCellText>
                {namesByWorkflow.get(run.workflowId) ?? t('unknownWorkflow')}
              </TableCellText>
            </td>
          ) : null}
          <td className="px-4 py-2">
            <TableCellText>{tCause.has(run.cause) ? tCause(run.cause) : run.cause}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{tActor(getActorWord(run.actingFor, caller))}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <div className="flex items-center gap-2">
              <RunStatusBadge status={run.status} />
              <ExposureBadge exposure={run.exposure} />
            </div>
          </td>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
