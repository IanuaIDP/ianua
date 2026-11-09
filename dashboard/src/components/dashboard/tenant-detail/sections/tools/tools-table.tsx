'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ToolActionsMenu } from '@/components/dashboard/tenant-detail/sections/tools/tool-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { Tool, ToolAction } from '@/types/tool';
import { getBadgeSoftColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { useToolOptions } from '@/hooks/dashboard/use-tool-options';

type ToolsTableProps = {
  isLoading?: boolean;
  onToolAction: (tool: Tool, action: ToolAction) => Promise<void> | void;
  onViewSchema: (tool: Tool) => void;
  tools: Tool[];
};

export function ToolsTable({
  isLoading = false,
  onToolAction,
  onViewSchema,
  tools,
}: ToolsTableProps) {
  const t = useTranslations('dashboard.tools');
  const { actionClassLabel } = useToolOptions();
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('columns.tool') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={tools.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {tools.map((tool) => (
        <tr key={tool.id} className="group transition hover:bg-hoverBg">
          <td className="px-4 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-white">{tool.name}</span>
              <span
                className={cn(
                  'inline-flex h-5 items-center rounded-md px-1.5 text-[10px] font-medium leading-none',
                  getBadgeSoftColorClass(tool.method),
                )}
              >
                {tool.method}
              </span>
              <TableCellText className="w-auto max-w-64 font-mono text-[10px] text-textGray">
                {tool.path}
              </TableCellText>
              <span
                className={cn(
                  'inline-flex h-5 items-center rounded-md px-1.5 text-[10px] font-medium leading-none',
                  getBadgeSoftColorClass(tool.actionClass),
                )}
              >
                {actionClassLabel(tool.actionClass)}
              </span>
            </div>
            <p className="mt-1 text-xs text-textGray">{tool.description}</p>
          </td>
          <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
            <div className="flex items-center justify-end gap-3">
              <DashboardStatusBadge status={tool.classification} />
              <DashboardStatusBadge status={tool.status} />
              <button
                type="button"
                onClick={() => onViewSchema(tool)}
                className="inline-flex h-7 items-center gap-1.5 rounded-md border border-borderGray px-2.5 text-[10px] font-medium text-white transition hover:bg-hoverBg"
              >
                <span className="material-symbols-rounded text-sm!" aria-hidden>
                  data_object
                </span>
                {t('viewSchema')}
              </button>
              <ToolActionsMenu tool={tool} onActionConfirm={onToolAction} />
            </div>
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
