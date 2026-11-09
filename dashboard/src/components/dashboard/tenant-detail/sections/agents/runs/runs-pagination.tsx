import { useTranslations } from 'next-intl';

type RunsPaginationProps = {
  page: number;
  limit: number;
  hasNext: boolean;
  isLoading: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onLimitChange: (limit: number) => void;
};

export function RunsPagination({
  page,
  limit,
  hasNext,
  isLoading,
  onPrevious,
  onNext,
  onLimitChange,
}: RunsPaginationProps) {
  const t = useTranslations('dashboard.agents.runs.pages');
  const tPages = useTranslations('dashboard.pagination');
  return (
    <footer className="flex shrink-0 flex-col items-stretch gap-2 border-t border-borderGray px-4 py-3 text-xs text-textGray sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-2">
        <label htmlFor="agent-runs-page-size" className="text-xs text-white">
          {tPages('rowsPerPage')}
        </label>
        <select
          id="agent-runs-page-size"
          value={limit}
          onChange={(event) => onLimitChange(Number(event.target.value))}
          className="h-8 min-w-16 rounded-lg border border-borderGray bg-surfaceInset px-3 text-white outline-none transition hover:bg-hoverBg"
        >
          {[20, 50, 100].map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </div>
      <nav aria-label={t('label')} className="flex items-center gap-5">
        <span aria-live="polite">{t('page', { page })}</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            aria-label={tPages('previous')}
            disabled={isLoading || page === 1}
            onClick={onPrevious}
            className="flex size-7 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white disabled:pointer-events-none disabled:opacity-40"
          >
            <span className="material-symbols-rounded" aria-hidden>
              chevron_left
            </span>
          </button>
          <button
            type="button"
            aria-label={tPages('next')}
            disabled={isLoading || !hasNext}
            onClick={onNext}
            className="flex size-7 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white disabled:pointer-events-none disabled:opacity-40"
          >
            <span className="material-symbols-rounded" aria-hidden>
              chevron_right
            </span>
          </button>
        </div>
      </nav>
    </footer>
  );
}
