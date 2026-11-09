import type { MouseEvent, ReactNode } from 'react';

import { cn } from '@/utils/cn';

type DashboardTableActionsCellProps = {
  children: ReactNode;
  className?: string;
  /**
   * Stops a click on the menu from also reaching a clickable row. Leave it on
   * unless the row should react to clicks inside this cell.
   */
  stopRowClick?: boolean;
};

/**
 * The row-actions cell of a `DashboardTableShell` table.
 *
 * Pinned to the right edge so the menu stays in reach however far a wide
 * table is scrolled. It needs a solid background to cover what scrolls
 * under it, so its row must carry `group` for the hover colour to follow.
 */
export function DashboardTableActionsCell({
  children,
  className,
  stopRowClick = true,
}: DashboardTableActionsCellProps) {
  return (
    <td
      className={cn(
        'sticky right-0 z-10 bg-cardBg px-3 py-2 text-right transition group-hover:bg-hoverBg',
        className,
      )}
      onClick={
        stopRowClick
          ? (event: MouseEvent<HTMLTableCellElement>) => event.stopPropagation()
          : undefined
      }
    >
      {children}
    </td>
  );
}
