'use client';

import { useTranslations } from 'next-intl';

import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { TableCellText } from '@/components/ui/table-cell';
import {
  WorkflowActionsMenu,
  type WorkflowAction,
} from '@/components/dashboard/workflows/workflow-actions-menu';
import { WorkflowStatusBadge } from '@/components/dashboard/workflows/workflow-badges';
import type { Workflow, WorkflowSortField } from '@/types/workflows';
import { formatBackendDateTime } from '@/utils/date';

type WorkflowsTableProps = {
  canRemove: boolean;
  canRun: boolean;
  emptyMessage: string;
  isLoading: boolean;
  onAction: (workflow: Workflow, action: WorkflowAction) => void;
  onRemove: (workflow: Workflow) => Promise<void>;
  onSortChange: (field: WorkflowSortField) => void;
  sortDirection?: 'asc' | 'desc';
  sortField?: WorkflowSortField;
  workflows: Workflow[];
};

function canStartByHand(workflow: Workflow) {
  return workflow.status === 'published' && workflow.trigger.type === 'manual';
}

/** The workflow list: name, what starts it, whether it is on, when it last changed. */
export function WorkflowsTable({
  canRemove,
  canRun,
  emptyMessage,
  isLoading,
  onAction,
  onRemove,
  onSortChange,
  sortDirection,
  sortField,
  workflows,
}: WorkflowsTableProps) {
  const t = useTranslations('dashboard.workflows.list');
  const tTrigger = useTranslations('dashboard.workflows.triggers');
  const columns: DashboardTableColumn<WorkflowSortField>[] = [
    { className: 'w-[42%]', label: t('columns.name'), sortField: 'name' },
    { className: 'w-[24%]', label: t('columns.starts') },
    { className: 'w-[16%]', label: t('columns.status') },
    { className: 'w-[18%]', label: t('columns.updated'), sortField: 'updated_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      emptyMessage={emptyMessage}
      hasActionsColumn
      isEmpty={workflows.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-190"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {workflows.map((workflow) => (
        <tr
          key={workflow.id}
          className="group h-11 cursor-pointer transition hover:bg-hoverBg"
          onClick={() => onAction(workflow, 'Open')}
        >
          <td className="px-4 py-2">
            <TableCellText className="font-semibold text-white">{workflow.name}</TableCellText>
            {workflow.needsAccount ? (
              <p className="mt-0.5 flex items-center gap-1 text-[10px] text-orange">
                <span className="material-symbols-rounded text-sm!" aria-hidden>
                  link_off
                </span>
                {t('needsAccount')}
              </p>
            ) : null}
          </td>
          <td className="px-4 py-2">
            <TableCellText>{tTrigger(workflow.trigger.type)}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <WorkflowStatusBadge status={workflow.status} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{formatBackendDateTime(workflow.updatedAt)}</TableCellText>
          </td>
          <DashboardTableActionsCell className="px-4 py-2">
            <div className="flex justify-end" onClick={(event) => event.stopPropagation()}>
              <WorkflowActionsMenu
                canRemove={canRemove && workflow.status !== 'archived'}
                canStart={canRun && canStartByHand(workflow)}
                onAction={(action) => onAction(workflow, action)}
                onRemove={() => onRemove(workflow)}
                workflowName={workflow.name}
              />
            </div>
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
