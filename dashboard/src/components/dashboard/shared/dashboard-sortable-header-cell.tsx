import { cn } from '@/utils/cn';

type DashboardSortableHeaderCellProps<SortField extends string> = {
  activeSortField?: SortField;
  className?: string;
  label: string;
  labelClassName?: string;
  onSortChange: (field: SortField) => void;
  sortDirection?: 'asc' | 'desc';
  sortField?: SortField;
};

export function DashboardSortableHeaderCell<SortField extends string>({
  activeSortField,
  className,
  label,
  labelClassName,
  onSortChange,
  sortDirection,
  sortField,
}: DashboardSortableHeaderCellProps<SortField>) {
  const isSorted = activeSortField === sortField;
  const isDescending = isSorted && sortDirection === 'desc';

  return (
    <th
      scope="col"
      className={cn('sticky top-0 z-10 h-8 bg-borderGray px-4 py-0 text-left', className)}
    >
      {sortField ? (
        <button
          type="button"
          onClick={() => onSortChange(sortField)}
          className={cn(
            'group inline-flex h-8 items-center gap-1 transition hover:text-white',
            isSorted && 'text-white',
            labelClassName,
          )}
        >
          <span>{label}</span>
          <span
            className={cn(
              'material-symbols-rounded inline-flex size-5 items-center justify-center text-lg! opacity-0 transition group-hover:opacity-100',
              isSorted ? 'text-primary opacity-100' : 'text-textGray',
              isDescending ? '-rotate-90' : 'rotate-90',
            )}
            style={{
              fontVariationSettings: "'OPSZ' 20, 'wght' 300, 'FILL' 0, 'GRAD' 0",
            }}
            aria-hidden="true"
          >
            arrow_right_alt
          </span>
        </button>
      ) : (
        <span className={labelClassName}>{label}</span>
      )}
    </th>
  );
}
