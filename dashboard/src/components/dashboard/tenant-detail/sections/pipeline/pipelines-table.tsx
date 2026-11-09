'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { PipelineActionsMenu } from '@/components/dashboard/tenant-detail/sections/pipeline/pipeline-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { PipelineAction, PipelineSummary } from '@/types/pipeline';

type PipelinesTableProps = {
  canUpdatePipeline?: boolean;
  isLoading?: boolean;
  onPipelineAction: (pipeline: PipelineSummary, action: PipelineAction) => Promise<void> | void;
  onSelect: (pipeline: PipelineSummary) => void;
  pipelines: PipelineSummary[];
};

export function PipelinesTable({
  canUpdatePipeline = true,
  isLoading = false,
  onPipelineAction,
  onSelect,
  pipelines,
}: PipelinesTableProps) {
  const t = useTranslations('dashboard.pipelines');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[30%]', label: t('columns.name') },
    { className: 'w-[14%]', label: t('columns.status') },
    { className: 'w-[12%]', label: t('columns.stages') },
    { className: 'w-[12%]', label: t('columns.routes') },
    { className: 'w-[16%]', label: t('columns.created') },
    { className: 'w-[16%]', label: t('columns.updated') },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn
      isEmpty={pipelines.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-180"
      onSortChange={() => undefined}
    >
      {pipelines.map((pipeline) => (
        <tr
          key={pipeline.id}
          className="group h-11 cursor-pointer transition hover:bg-hoverBg"
          onClick={() => onSelect(pipeline)}
        >
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{pipeline.name}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={pipeline.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pipeline.stageCount}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pipeline.routeCount}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pipeline.created}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <TableCellText>{pipeline.updated}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            <PipelineActionsMenu
              canUpdate={canUpdatePipeline}
              pipeline={pipeline}
              onActionConfirm={onPipelineAction}
            />
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
