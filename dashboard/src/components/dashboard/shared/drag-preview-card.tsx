import type { ReactNode } from 'react';

import type { DragReorderRect } from '@/hooks/dashboard/use-drag-reorder';

type DragPreviewCardProps = {
  children: ReactNode;
  insetPx?: number;
  pointerY: number;
  rect: DragReorderRect;
};

export function DragPreviewCard({ children, insetPx = 16, pointerY, rect }: DragPreviewCardProps) {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed z-50 flex items-center gap-3 rounded-lg border border-borderGray bg-surfaceChip px-4 py-3 shadow-dropdown"
      style={{
        left: rect.left + insetPx,
        top: pointerY,
        transform: 'translateY(-50%)',
        width: rect.width - insetPx * 2,
      }}
    >
      {children}
    </div>
  );
}
