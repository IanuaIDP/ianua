'use client';

import type { ReactNode, UIEvent } from 'react';
import { useEffect, useRef, useState } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardSortableHeaderCell } from '@/components/dashboard/shared/dashboard-sortable-header-cell';
import { cn } from '@/utils/cn';

export type DashboardTableColumn<SortField extends string> = {
  className?: string;
  label: string;
  labelClassName?: string;
  sortField?: SortField;
};

type DashboardTableShellProps<SortField extends string> = {
  children: ReactNode;
  className?: string;
  columns: DashboardTableColumn<SortField>[];
  emptyMessage?: ReactNode;
  hasActionsColumn?: boolean;
  isEmpty: boolean;
  isLoading: boolean;
  loadingMessage: string;
  minWidthClassName: string;
  /**
   * Least width in pixels, for a table whose columns are data rather than
   * markup. A count known only at runtime cannot name a utility class, and
   * `table-fixed` would otherwise scale every column down to fit instead of
   * letting the table scroll.
   */
  minWidth?: number;
  onSortChange: (field: SortField) => void;
  sortDirection?: 'asc' | 'desc';
  sortField?: SortField;
};

export function DashboardTableShell<SortField extends string>({
  children,
  className,
  columns,
  emptyMessage,
  hasActionsColumn = false,
  isEmpty,
  isLoading,
  loadingMessage,
  minWidth,
  minWidthClassName,
  onSortChange,
  sortDirection,
  sortField,
}: DashboardTableShellProps<SortField>) {
  const t = useTranslations('common');
  const headerScrollRef = useRef<HTMLDivElement>(null);
  const bodyScrollRef = useRef<HTMLDivElement>(null);
  // The body's vertical scrollbar narrows it; the header has none. Leaving the
  // header that much narrower too keeps both scrolling the same distance, so
  // their columns stay lined up all the way to the right edge.
  const [scrollbarWidth, setScrollbarWidth] = useState(0);
  const colSpan = columns.length + (hasActionsColumn ? 1 : 0);
  // Both tables carry it, or the header stops lining up with the body.
  const tableStyle = minWidth ? { minWidth: `${minWidth}px` } : undefined;
  const colGroup = (
    <colgroup>
      {columns.map((column) => (
        <col key={column.label} className={column.className} />
      ))}
      {hasActionsColumn ? <col className="w-12" /> : null}
    </colgroup>
  );

  function syncHeaderScroll(event: UIEvent<HTMLDivElement>) {
    if (headerScrollRef.current) {
      headerScrollRef.current.scrollLeft = event.currentTarget.scrollLeft;
    }
  }

  useEffect(() => {
    const node = bodyScrollRef.current;

    if (!node) {
      return;
    }

    function measureScrollbar() {
      if (!node) {
        return;
      }

      setScrollbarWidth(node.offsetWidth - node.clientWidth);

      // A new scroll range can leave the header behind the body.
      if (headerScrollRef.current) {
        headerScrollRef.current.scrollLeft = node.scrollLeft;
      }
    }

    measureScrollbar();

    const resizeObserver = new ResizeObserver(measureScrollbar);
    resizeObserver.observe(node);

    const table = node.querySelector('table');

    if (table) {
      resizeObserver.observe(table);
    }

    return () => {
      resizeObserver.disconnect();
    };
  }, [children, isEmpty, isLoading]);

  return (
    <div className={cn('relative flex min-h-0 flex-1 flex-col overflow-hidden', className)}>
      <div className="shrink-0 bg-borderGray">
        <div
          ref={headerScrollRef}
          className="overflow-hidden"
          style={scrollbarWidth ? { marginRight: `${scrollbarWidth}px` } : undefined}
        >
          <table
            className={cn('w-full table-fixed text-left', minWidthClassName)}
            style={tableStyle}
          >
            {colGroup}
            <thead className="text-xs font-extrabold text-textGray">
              <tr>
                {columns.map((column) => (
                  <DashboardSortableHeaderCell
                    key={column.label}
                    activeSortField={sortField}
                    className={column.className}
                    label={column.label}
                    labelClassName={column.labelClassName}
                    sortDirection={sortDirection}
                    sortField={column.sortField}
                    onSortChange={onSortChange}
                  />
                ))}
                {hasActionsColumn ? (
                  <th
                    scope="col"
                    className="sticky top-0 right-0 z-20 w-12 bg-borderGray px-3 py-2.5"
                  >
                    <span className="sr-only">Actions</span>
                  </th>
                ) : null}
              </tr>
            </thead>
          </table>
        </div>
      </div>

      <div ref={bodyScrollRef} className="min-h-0 flex-1 overflow-auto" onScroll={syncHeaderScroll}>
        <table className={cn('w-full table-fixed text-left', minWidthClassName)} style={tableStyle}>
          {colGroup}
          <tbody className="divide-y divide-borderGray text-xs text-white">
            {isLoading ? (
              <tr>
                <td
                  colSpan={colSpan}
                  className="h-36 px-4 text-center text-xs font-medium text-textGray"
                >
                  {loadingMessage}
                </td>
              </tr>
            ) : isEmpty ? (
              <tr>
                <td
                  colSpan={colSpan}
                  className="h-36 px-4 text-center text-xs font-medium text-textGray"
                >
                  <span className="inline-flex items-center gap-2">
                    <span className="material-symbols-rounded">feedback</span>
                    {emptyMessage ?? t('nothingHere')}
                  </span>
                </td>
              </tr>
            ) : (
              children
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
