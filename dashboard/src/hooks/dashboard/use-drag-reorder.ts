'use client';

import { useEffect, useState } from 'react';
import type { DragEvent } from 'react';

export type DragReorderPosition = 'before' | 'after';
export type DragReorderAxis = 'horizontal' | 'vertical';
export type DragReorderLayout = 'grid' | 'list';

export type DragReorderRect = {
  left: number;
  width: number;
};

type DropTarget = {
  axis: DragReorderAxis;
  id: string;
  position: DragReorderPosition;
};

export type DragReorderDraggableProps = {
  draggable: boolean;
  onDragEnd?: () => void;
  onDragStart?: (event: DragEvent<HTMLElement>) => void;
};

export type DragReorderDropTargetProps = {
  onDragOver: (event: DragEvent<HTMLElement>) => void;
  onDrop: (event: DragEvent<HTMLElement>) => void;
};

export type DragReorderRowProps = {
  draggableProps: DragReorderDraggableProps;
  dropIndicatorAxis: DragReorderAxis | null;
  dropIndicatorPosition: DragReorderPosition | null;
  dropTargetProps: DragReorderDropTargetProps;
  isDragging: boolean;
};

type UseDragReorderOptions<T> = {
  getId: (item: T) => string;
  isDraggable?: (item: T) => boolean;
  isDropTarget?: (item: T) => boolean;
  items: T[];
  layout?: DragReorderLayout;
  onDrop: (fromId: string, targetId: string, position: DragReorderPosition) => void;
};

let transparentDragImage: HTMLImageElement | null = null;

function getTransparentDragImage() {
  if (!transparentDragImage && typeof Image !== 'undefined') {
    transparentDragImage = new Image();
    transparentDragImage.src =
      'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==';
  }

  return transparentDragImage;
}

function getDropPosition(
  event: DragEvent<HTMLElement>,
  layout: DragReorderLayout,
): { axis: DragReorderAxis; position: DragReorderPosition } {
  const rect = event.currentTarget.getBoundingClientRect();
  const verticalRatio = rect.height > 0 ? (event.clientY - rect.top) / rect.height : 0.5;
  const verticalPosition: DragReorderPosition = verticalRatio < 0.5 ? 'before' : 'after';

  if (layout === 'list') {
    return { axis: 'vertical', position: verticalPosition };
  }

  const horizontalRatio = rect.width > 0 ? (event.clientX - rect.left) / rect.width : 0.5;
  const horizontalPosition: DragReorderPosition = horizontalRatio < 0.5 ? 'before' : 'after';

  const verticalDistanceFromCenter = Math.abs(verticalRatio - 0.5);
  const horizontalDistanceFromCenter = Math.abs(horizontalRatio - 0.5);

  if (horizontalDistanceFromCenter >= verticalDistanceFromCenter) {
    return { axis: 'horizontal', position: horizontalPosition };
  }

  return { axis: 'vertical', position: verticalPosition };
}

export function useDragReorder<T>({
  getId,
  isDraggable,
  isDropTarget,
  items,
  layout = 'list',
  onDrop,
}: UseDragReorderOptions<T>) {
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<DropTarget | null>(null);
  const [pointerY, setPointerY] = useState<number | null>(null);
  const [dragPreviewRect, setDragPreviewRect] = useState<DragReorderRect | null>(null);

  useEffect(() => {
    if (!draggedId) {
      return;
    }

    function handleDocumentDragOver(event: globalThis.DragEvent) {
      setPointerY(event.clientY);
    }

    document.addEventListener('dragover', handleDocumentDragOver);

    return () => document.removeEventListener('dragover', handleDocumentDragOver);
  }, [draggedId]);

  function reset() {
    setDraggedId(null);
    setDropTarget(null);
    setPointerY(null);
    setDragPreviewRect(null);
  }

  function getRowProps(item: T): DragReorderRowProps {
    const id = getId(item);
    const canDrag = isDraggable ? isDraggable(item) : true;
    const canReceiveDrop = isDropTarget ? isDropTarget(item) : true;

    function handleDragStart(event: DragEvent<HTMLElement>) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', id);

      const dragImage = getTransparentDragImage();

      if (dragImage) {
        event.dataTransfer.setDragImage(dragImage, 0, 0);
      }

      const rect = event.currentTarget.getBoundingClientRect();
      setDraggedId(id);
      setDragPreviewRect({ left: rect.left, width: rect.width });
    }

    function handleDragOver(event: DragEvent<HTMLElement>) {
      if (!draggedId || draggedId === id || !canReceiveDrop) {
        return;
      }

      event.preventDefault();
      const { axis, position } = getDropPosition(event, layout);
      setDropTarget({ axis, id, position });
    }

    function handleDropEvent(event: DragEvent<HTMLElement>) {
      if (!draggedId || !canReceiveDrop) {
        return;
      }

      event.preventDefault();
      const { position } = getDropPosition(event, layout);
      const fromId = draggedId;
      reset();

      if (fromId !== id) {
        onDrop(fromId, id, position);
      }
    }

    const activeDropTarget = dropTarget?.id === id ? dropTarget : null;

    return {
      draggableProps: {
        draggable: canDrag,
        onDragEnd: canDrag ? reset : undefined,
        onDragStart: canDrag ? handleDragStart : undefined,
      },
      dropIndicatorAxis: activeDropTarget?.axis ?? null,
      dropIndicatorPosition: activeDropTarget?.position ?? null,
      dropTargetProps: {
        onDragOver: handleDragOver,
        onDrop: handleDropEvent,
      },
      isDragging: draggedId === id,
    };
  }

  const draggedItem = items.find((item) => getId(item) === draggedId) ?? null;
  const lastItem = items.length > 0 ? items[items.length - 1] : null;
  const isDropAfterLastItem = Boolean(
    dropTarget && lastItem && dropTarget.id === getId(lastItem) && dropTarget.position === 'after',
  );

  return {
    draggedId,
    draggedItem,
    dragPreviewRect,
    dropTarget,
    getRowProps,
    isDropAfterLastItem,
    pointerY,
  };
}

export function reorderById<T>(
  items: T[],
  getId: (item: T) => string,
  fromId: string,
  targetId: string,
  position: DragReorderPosition,
): T[] {
  const fromIndex = items.findIndex((item) => getId(item) === fromId);
  let toIndex = items.findIndex((item) => getId(item) === targetId);

  if (fromIndex === -1 || toIndex === -1) {
    return items;
  }

  if (position === 'after') {
    toIndex += 1;
  }

  if (fromIndex === toIndex || fromIndex === toIndex - 1) {
    return items;
  }

  const next = [...items];
  const [moved] = next.splice(fromIndex, 1);
  const insertIndex = fromIndex < toIndex ? toIndex - 1 : toIndex;
  next.splice(insertIndex, 0, moved);

  return next;
}
