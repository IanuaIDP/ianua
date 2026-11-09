'use client';

import { useState } from 'react';

export type TableSortDirection = 'asc' | 'desc';

type UseTableQueryStateOptions<SortField extends string> = {
  initialRowsPerPage?: number;
  initialSortDirection?: TableSortDirection;
  initialSortField?: SortField;
};

export function useTableQueryState<SortField extends string>(
  options: UseTableQueryStateOptions<SortField> = {},
) {
  const { initialRowsPerPage = 20, initialSortDirection, initialSortField } = options;
  const [pageCursors, setPageCursors] = useState<string[]>([]);
  const [rowsPerPage, setRowsPerPage] = useState(initialRowsPerPage);
  const [sortField, setSortField] = useState<SortField | undefined>(initialSortField);
  const [sortDirection, setSortDirection] = useState<TableSortDirection | undefined>(
    initialSortDirection,
  );
  const after = pageCursors.at(-1);
  const currentPage = pageCursors.length + 1;

  function handleNextPage(nextCursor: string) {
    setPageCursors((cursors) => [...cursors, nextCursor]);
  }

  function handlePreviousPage() {
    setPageCursors((cursors) => cursors.slice(0, -1));
  }

  function handleRowsPerPageChange(value: number) {
    setRowsPerPage(value);
    resetToFirstPage();
  }

  function handleSortChange(field: SortField) {
    resetToFirstPage();

    if (sortField !== field) {
      setSortField(field);
      setSortDirection('asc');
      return;
    }

    if (sortDirection === 'asc') {
      setSortDirection('desc');
      return;
    }

    setSortField(undefined);
    setSortDirection(undefined);
  }

  function resetToFirstPage() {
    setPageCursors([]);
  }

  return {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    resetToFirstPage,
    rowsPerPage,
    sortDirection,
    sortField,
  };
}
