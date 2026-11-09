'use client';

import { Fragment, useMemo, useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { AuditLogDetails } from '@/components/dashboard/settings/sections/audit/audit-log-details';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { Button } from '@/components/ui/Button';
import { DateInput, type DateRange } from '@/components/ui/date-input';
import { useNotification } from '@/components/ui/notifications';
import { SearchInput } from '@/components/ui/search-input';
import { TableCellStack, TableCellText } from '@/components/ui/table-cell';
import { useDebouncedValue } from '@/hooks/dashboard/use-debounced-value';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { getTenantManagementPath } from '@/utils/dashboard-routes';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getAuditLog,
  startAuditLogExport,
  waitForAuditLogExport,
} from '@/lib/api';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useAuthStore } from '@/store/auth-store';
import type { AuditLogSortDirection, AuditLogSortField } from '@/types/audit-log';
import { getBadgeColorClass, getBadgeSoftColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { getInitials } from '@/utils/initials';
import { toDateFilterValue } from '@/lib/audit/date-filter-value';

function getScopeBadgeColor(eventScope: string) {
  return eventScope === 'Organization' ? 'bg-white/15' : getBadgeSoftColorClass(eventScope);
}

export function AuditLogSettingsSection() {
  const t = useTranslations('dashboard.settings.audit');
  const tErrors = useTranslations('common.errors');
  const columns: DashboardTableColumn<AuditLogSortField>[] = [
    { className: 'w-14', label: '' },
    {
      className: 'w-[33%]',
      label: t('columns.event'),
      labelClassName: '-ml-4',
      sortField: 'event_type',
    },
    { className: 'w-[22%]', label: t('columns.author') },
    { className: 'w-[19%]', label: t('columns.ip') },
    { className: 'w-[21%]', label: t('columns.timestamp'), sortField: 'occurred_at' },
  ];
  const { showNotification } = useNotification();
  const currentUserEmail = useAuthStore((state) => state.user?.email);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const { role } = useOrgAccess();
  const canExport = role !== 'Billing';
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    resetToFirstPage,
    rowsPerPage,
  } = useTableQueryState<AuditLogSortField>({ initialRowsPerPage: 50 });
  const [dateRange, setDateRange] = useState<DateRange>();
  const [expandedEntryIds, setExpandedEntryIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebouncedValue(search);
  const [sortField, setSortField] = useState<AuditLogSortField>('occurred_at');
  const [sortDirection, setSortDirection] = useState<AuditLogSortDirection>('desc');
  const hasActiveFilters = Boolean(search.trim() || dateRange?.from || dateRange?.to);

  const dateFilters = useMemo(
    () => ({
      before: toDateFilterValue(dateRange?.to, 'end'),
      since: toDateFilterValue(dateRange?.from, 'start'),
    }),
    [dateRange],
  );

  const {
    data: auditLogList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () =>
      getAuditLog(organizationSlug ?? '', {
        after,
        before: dateFilters.before,
        limit: rowsPerPage,
        search: debouncedSearch.trim() || undefined,
        since: dateFilters.since,
        sortDirection,
        sortField,
      }),
    queryKey: [
      'audit-log',
      organizationSlug,
      debouncedSearch,
      dateFilters.since,
      dateFilters.before,
      sortField,
      sortDirection,
      after,
      rowsPerPage,
    ],
  });
  const { isPending: isExportingCsv, mutate: exportCsv } = useMutation({
    mutationFn: async () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      const exportId = await startAuditLogExport(organizationSlug, {
        before: dateFilters.before,
        eventType: debouncedSearch.trim() || undefined,
        since: dateFilters.since,
      });

      return waitForAuditLogExport(organizationSlug, exportId);
    },
    onMutate: () => {
      showNotification({ message: t('exportStarted'), type: 'default' });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('exportFailed')),
        type: 'error',
      });
    },
    onSuccess: (downloadUrl) => window.location.assign(downloadUrl),
  });

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  function handleSortChange(field: AuditLogSortField) {
    resetToFirstPage();

    if (sortField !== field) {
      setSortField(field);
      setSortDirection('asc');
      return;
    }

    setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'));
  }

  function handleClearFilters() {
    setSearch('');
    setDateRange(undefined);
    resetToFirstPage();
  }

  function toggleEntryExpanded(id: string) {
    setExpandedEntryIds((current) => {
      const next = new Set(current);

      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }

      return next;
    });
  }

  return (
    <SettingsCard
      title={t('title')}
      description={t('description')}
      className="flex max-h-[calc(100vh-5.25rem)] min-h-0 flex-col overflow-hidden"
      headerAction={
        <Button
          type="button"
          variant="outline"
          disabled={!organizationSlug || !canExport}
          isLoading={isExportingCsv}
          onClick={() => exportCsv()}
          className="flex w-auto items-center gap-2 border-borderGray bg-surfaceChip px-4 py-1.5 text-sm font-semibold text-white hover:bg-hoverBg"
        >
          <span className="material-symbols-rounded text-lg!" aria-hidden="true">
            download
          </span>
          {t('exportCsv')}
        </Button>
      }
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="w-full sm:w-[34%]">
          <SearchInput
            value={search}
            onClear={() => {
              setSearch('');
              resetToFirstPage();
            }}
            onChange={(event) => {
              setSearch(event.target.value);
              resetToFirstPage();
            }}
            placeholder={t('searchPlaceholder')}
          />
        </div>
        <div className="w-full sm:w-[34%]">
          <DateInput
            disableFutureDates
            value={dateRange}
            onChange={(value) => {
              setDateRange(value);
              resetToFirstPage();
            }}
          />
        </div>

        {hasActiveFilters ? (
          <Button
            type="button"
            onClick={handleClearFilters}
            variant="outline"
            className="flex w-auto shrink-0 items-center gap-2 border-transparent bg-transparent px-2 py-1.5 text-xs font-medium text-textGray hover:bg-hoverBg hover:text-white"
          >
            <span className="material-symbols-rounded" aria-hidden="true">
              close
            </span>
            {t('clearAll')}
          </Button>
        ) : null}
      </div>

      {errorMessage ? <p className="mt-4 text-sm font-medium text-error">{errorMessage}</p> : null}

      <div className="relative -mx-4 -mb-4 mt-4 flex min-h-0 flex-1 flex-col overflow-hidden rounded-b-lg">
        <DashboardTableShell
          columns={columns}
          isEmpty={!auditLogList?.items.length}
          isLoading={isLoading}
          loadingMessage={t('loading')}
          emptyMessage={t('empty')}
          minWidthClassName="min-w-210"
          onSortChange={handleSortChange}
          sortDirection={sortDirection}
          sortField={sortField}
        >
          {auditLogList?.items.map((entry) => {
            const hasDetails = Boolean(entry.details);
            const isExpanded = hasDetails && expandedEntryIds.has(entry.id);

            return (
              <Fragment key={entry.id}>
                <tr className={cn('h-11 transition hover:bg-hoverBg', isExpanded && 'border-b-0')}>
                  <td className="px-4 py-2">
                    {hasDetails ? (
                      <button
                        type="button"
                        aria-expanded={isExpanded}
                        aria-label={isExpanded ? t('collapse') : t('expand')}
                        onClick={() => toggleEntryExpanded(entry.id)}
                        className="flex size-6 items-center justify-center rounded-md text-textGray transition hover:text-white"
                      >
                        <span
                          className={cn(
                            'material-symbols-rounded text-lg! transition-transform',
                            isExpanded ? 'rotate-90 text-primary' : 'text-textGray',
                          )}
                          aria-hidden="true"
                        >
                          chevron_right
                        </span>
                      </button>
                    ) : null}
                  </td>
                  <td className="py-2 pr-4">
                    <div className="flex min-w-0 items-center gap-3">
                      {entry.tenantSlug ? (
                        <Link
                          href={getTenantManagementPath(entry.tenantSlug)}
                          className={cn(
                            'inline-flex shrink-0 rounded-md px-2 py-0.5 text-[10px] font-semibold text-white transition hover:opacity-80',
                            getScopeBadgeColor(entry.eventScope),
                          )}
                        >
                          {entry.eventScope}
                        </Link>
                      ) : (
                        <span
                          className={cn(
                            'inline-flex shrink-0 rounded-md px-2 py-0.5 text-[10px] font-semibold text-white',
                            getScopeBadgeColor(entry.eventScope),
                          )}
                        >
                          {entry.eventScope}
                        </span>
                      )}
                      <TableCellText className="font-semibold text-white">
                        {entry.event}
                      </TableCellText>
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className={cn(
                          'flex size-6 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white',
                          getBadgeColorClass(entry.actorEmail ?? entry.actor),
                        )}
                      >
                        {getInitials(entry.actor)}
                      </span>
                      {entry.actorEmail ? (
                        <TableCellStack
                          primary={
                            currentUserEmail &&
                            entry.actorEmail.toLowerCase() === currentUserEmail.toLowerCase()
                              ? t('me', { name: entry.actor })
                              : entry.actor
                          }
                          primaryClassName="font-semibold text-white"
                          secondary={entry.actorEmail}
                          secondaryClassName="text-[10px] font-medium text-textGray"
                        />
                      ) : (
                        <TableCellText className="font-semibold text-white">
                          {entry.actor}
                        </TableCellText>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2 font-medium text-white">
                    <TableCellText>{entry.ip}</TableCellText>
                  </td>
                  <td className="px-4 py-2 font-medium text-white">
                    <TableCellText>{entry.dateTime}</TableCellText>
                  </td>
                </tr>
                {isExpanded && entry.details ? (
                  <tr>
                    <td className="px-4 py-0" />
                    <td colSpan={columns.length - 1} className="px-4 py-0">
                      <AuditLogDetails details={entry.details} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </DashboardTableShell>

        <DashboardPagination
          currentPage={currentPage}
          itemCount={auditLogList?.items.length ?? 0}
          nextCursor={auditLogList?.nextCursor ?? null}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="audit-log-rows-per-page"
        />
      </div>
    </SettingsCard>
  );
}
