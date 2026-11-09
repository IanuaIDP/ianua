import { useTranslations } from 'next-intl';

import { DASHBOARD_ROWS_PER_PAGE_OPTIONS } from '@/constants/dashboard';

type DashboardPaginationProps = {
  currentPage: number;
  itemCount: number;
  nextCursor: string | null;
  onNext: (nextCursor: string) => void;
  onPrevious: () => void;
  onRowsPerPageChange: (rowsPerPage: number) => void;
  rowsPerPage: number;
  rowsPerPageSelectId: string;
};

export function DashboardPagination({
  currentPage,
  itemCount,
  nextCursor,
  onNext,
  onPrevious,
  onRowsPerPageChange,
  rowsPerPage,
  rowsPerPageSelectId,
}: DashboardPaginationProps) {
  const t = useTranslations('dashboard.pagination');
  const isFirstPage = currentPage <= 1;
  const startItem = itemCount === 0 ? 0 : (currentPage - 1) * rowsPerPage + 1;
  const endItem = itemCount === 0 ? 0 : startItem + itemCount - 1;

  return (
    <footer className="flex shrink-0 flex-col items-stretch gap-2 border-t border-borderGray px-4 py-3 text-xs text-textGray sm:h-12 sm:min-h-12 sm:flex-row sm:items-center sm:justify-between sm:gap-0 sm:py-0">
      <div className="flex items-center gap-2">
        <label htmlFor={rowsPerPageSelectId} className="text-xs text-white">
          {t('rowsPerPage')}
        </label>
        <div className="relative">
          <select
            id={rowsPerPageSelectId}
            value={rowsPerPage}
            onChange={(event) => onRowsPerPageChange(Number(event.target.value))}
            className="h-8 min-w-16 appearance-none rounded-lg border border-borderGray bg-surfaceInset px-3 pr-8 text-white outline-none transition hover:bg-hoverBg"
          >
            {DASHBOARD_ROWS_PER_PAGE_OPTIONS.map((option) => (
              <option key={option} value={option} className="bg-cardBg text-white">
                {option}
              </option>
            ))}
          </select>
          <span
            className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-textGray"
            aria-hidden="true"
          >
            <span className="material-symbols-rounded">arrow_drop_down</span>
          </span>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <span>{t('pageRange', { end: endItem, start: startItem })}</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            aria-label={t('previous')}
            disabled={isFirstPage}
            onClick={onPrevious}
            className="flex size-7 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white disabled:pointer-events-none disabled:opacity-40"
          >
            <span className="material-symbols-rounded">chevron_left</span>
          </button>
          <button
            type="button"
            aria-label={t('next')}
            disabled={!nextCursor}
            onClick={() => nextCursor && onNext(nextCursor)}
            className="flex size-7 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white disabled:pointer-events-none disabled:opacity-40"
          >
            <span className="material-symbols-rounded">chevron_right</span>
          </button>
        </div>
      </div>
    </footer>
  );
}
