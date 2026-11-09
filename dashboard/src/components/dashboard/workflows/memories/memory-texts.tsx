'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { ExposureBadge } from '@/components/dashboard/workflows/workflow-badges';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, getMemoryEntries } from '@/lib/api';
import { formatBackendDateTime } from '@/utils/date';

/** A memory's texts, oldest first, page by page. */
export function MemoryTexts({ memoryId }: { memoryId: string }) {
  const t = useTranslations('dashboard.memories.texts');
  const tPagination = useTranslations('dashboard.pagination');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { after, currentPage, handleNextPage, handlePreviousPage } = useTableQueryState<never>();
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getMemoryEntries(orgSlug ?? '', tenantSlug, memoryId, after),
    queryKey: ['memory-entries', orgSlug, tenantSlug, memoryId, after],
    retry: false,
  });
  const entries = data?.entries ?? [];

  return (
    <section className="rounded-lg border border-borderGray bg-cardBg">
      <div className="p-4">
        <h2 className="text-base font-bold text-white">{t('title')}</h2>
        <p className="mt-1 text-xs text-textGray">{t('description')}</p>
      </div>

      {error ? (
        <p className="px-4 pb-4 text-xs text-error">{getApiErrorMessage(error, t('loadFailed'))}</p>
      ) : null}

      {isLoading ? <p className="px-4 pb-4 text-xs text-textGray">{t('loading')}</p> : null}

      {!isLoading && !error && entries.length === 0 ? (
        <p className="px-4 pb-4 text-xs text-textGray">{t('empty')}</p>
      ) : null}

      <ul className="flex flex-col">
        {entries.map((entry) => (
          <li key={entry.id} className="border-t border-borderGray px-4 py-3">
            <p className="whitespace-pre-wrap text-xs text-white">{entry.text}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-textGray">
              <ExposureBadge exposure={entry.exposure} />
              <span>{formatBackendDateTime(entry.keptAt)}</span>
            </div>
          </li>
        ))}
      </ul>

      {currentPage > 1 || data?.nextCursor ? (
        <div className="flex justify-end gap-3 border-t border-borderGray px-4 py-3 text-xs">
          <button
            className="font-semibold text-primary disabled:text-textGray"
            disabled={currentPage === 1}
            type="button"
            onClick={handlePreviousPage}
          >
            {tPagination('previous')}
          </button>
          <button
            className="font-semibold text-primary disabled:text-textGray"
            disabled={!data?.nextCursor}
            type="button"
            onClick={() => data?.nextCursor && handleNextPage(data.nextCursor)}
          >
            {tPagination('next')}
          </button>
        </div>
      ) : null}
    </section>
  );
}
