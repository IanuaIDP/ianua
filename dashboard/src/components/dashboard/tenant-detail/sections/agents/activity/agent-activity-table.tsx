'use client';

import { useLocale, useTranslations } from 'next-intl';

import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import type { AgentActivityEvent, AgentActivitySortField } from '@/types/activity';
import { getActivityIcon, getActivitySummary, formatActivityTitle } from '@/utils/activity';
import { cn } from '@/utils/cn';
import { formatRelativeTime, parseBackendTimestamp } from '@/utils/date';

type AgentActivityTableProps = {
  events: AgentActivityEvent[];
  isLoading?: boolean;
  onSortChange: (field: AgentActivitySortField) => void;
  sortDirection?: 'asc' | 'desc';
  sortField?: AgentActivitySortField;
};

export function AgentActivityTable({
  events,
  isLoading = false,
  onSortChange,
  sortDirection,
  sortField,
}: AgentActivityTableProps) {
  const t = useTranslations('dashboard.agents.activity');
  const locale = useLocale();
  const columns: DashboardTableColumn<AgentActivitySortField>[] = [
    { className: 'w-full', label: t('title'), sortField: 'occurred_at' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={events.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      emptyMessage={t('empty')}
      minWidthClassName="min-w-160"
      onSortChange={onSortChange}
      sortDirection={sortDirection}
      sortField={sortField}
    >
      {events.map((event) => {
        const icon = getActivityIcon(event.eventType);
        const summaryEntries = getActivitySummary(event);
        const occurredAt = parseBackendTimestamp(event.occurredAt);

        return (
          <tr key={event.id} className="transition hover:bg-hoverBg">
            <td className="px-4 py-3">
              <div className="flex items-center justify-between gap-4">
                <div className="flex min-w-0 items-center gap-3">
                  <span
                    className={cn('material-symbols-rounded shrink-0 text-xl!', icon.className)}
                    aria-hidden
                  >
                    {icon.icon}
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-white">
                      {formatActivityTitle(event.eventType)}
                    </p>
                    {summaryEntries.length > 0 ? (
                      <p className="mt-0.5 truncate text-xs text-textGray">
                        {summaryEntries.map((entry, index) => (
                          <span key={entry.key}>
                            {index > 0 ? ' · ' : null}
                            {entry.key}: <span className="text-white">{entry.value}</span>
                          </span>
                        ))}
                      </p>
                    ) : null}
                  </div>
                </div>
                <span className="shrink-0 text-xs text-textGray">
                  {occurredAt ? formatRelativeTime(occurredAt, locale) : t('notAvailable')}
                </span>
              </div>
            </td>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
