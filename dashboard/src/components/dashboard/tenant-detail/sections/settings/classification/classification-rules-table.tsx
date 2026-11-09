'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { ClassificationRuleActionsMenu } from '@/components/dashboard/tenant-detail/sections/settings/classification/classification-rule-actions-menu';
import { TableCellText } from '@/components/ui/table-cell';
import type { ClassificationRule } from '@/types/classification';

type ClassificationRulesTableProps = {
  className?: string;
  canUpdate?: boolean;
  isLoading?: boolean;
  onRemoveConfirm: (rule: ClassificationRule) => Promise<void> | void;
  rules: ClassificationRule[];
};

export function ClassificationRulesTable({
  className = 'mt-4',
  canUpdate = false,
  isLoading = false,
  onRemoveConfirm,
  rules,
}: ClassificationRulesTableProps) {
  const t = useTranslations('dashboard.tenantSettings.classification');
  const columns: DashboardTableColumn<string>[] = [
    { className: 'w-[42%]', label: t('columns.field') },
    { className: 'w-[20%]', label: t('columns.sensitivity') },
    { className: 'w-[28%]', label: t('columns.action') },
  ];

  return (
    <DashboardTableShell
      className={className}
      columns={columns}
      emptyMessage={t('empty')}
      hasActionsColumn
      isEmpty={rules.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-150"
      onSortChange={() => {}}
    >
      {rules.map((rule) => (
        <tr key={rule.id} className="group h-11 transition hover:bg-hoverBg">
          <td className="px-4 py-2">
            <TableCellText className="font-mono text-white">{rule.fieldPath}</TableCellText>
          </td>
          <td className="px-4 py-2">
            <DashboardStatusBadge status={rule.level} />
          </td>
          <td className="px-4 py-2">
            <TableCellText>{t(`redaction.${rule.redaction}`)}</TableCellText>
          </td>
          <DashboardTableActionsCell>
            {canUpdate ? (
              <ClassificationRuleActionsMenu rule={rule} onRemoveConfirm={onRemoveConfirm} />
            ) : null}
          </DashboardTableActionsCell>
        </tr>
      ))}
    </DashboardTableShell>
  );
}
