'use client';

import { useTranslations } from 'next-intl';

import { DragInsertionLine } from '@/components/dashboard/shared/drag-insertion-line';
import { DragPreviewCard } from '@/components/dashboard/shared/drag-preview-card';
import { FlowNodeCard } from '@/components/dashboard/tenant-detail/sections/flows/flow-node-card';
import { useDragReorder } from '@/hooks/dashboard/use-drag-reorder';
import type { DragReorderPosition, DragReorderRowProps } from '@/hooks/dashboard/use-drag-reorder';
import type { FlowNodeDraft } from '@/types/flow-builder';
import { cn } from '@/utils/cn';

type FlowStageBlockProps = DragReorderRowProps & {
  errorMessage?: string;
  nodes: FlowNodeDraft[];
  showRemoveStage: boolean;
  stageNumber: number;
  onAddNode: () => void;
  onEditNode: (clientId: string) => void;
  onRemoveNode: (clientId: string) => void;
  onRemoveStage: () => void;
  onReorderNodes: (
    fromClientId: string,
    targetClientId: string,
    position: DragReorderPosition,
  ) => void;
};

export function FlowStageBlock({
  draggableProps,
  dropIndicatorPosition,
  dropTargetProps,
  errorMessage,
  isDragging,
  nodes,
  showRemoveStage,
  stageNumber,
  onAddNode,
  onEditNode,
  onRemoveNode,
  onRemoveStage,
  onReorderNodes,
}: FlowStageBlockProps) {
  const t = useTranslations('dashboard.flows');
  const {
    dragPreviewRect: nodeDragPreviewRect,
    draggedItem: draggedNode,
    getRowProps: getNodeRowProps,
    pointerY: nodePointerY,
  } = useDragReorder<FlowNodeDraft>({
    getId: (node) => node.clientId,
    items: nodes,
    layout: 'grid',
    onDrop: onReorderNodes,
  });

  return (
    <div className="relative">
      {dropIndicatorPosition ? (
        <DragInsertionLine
          className={cn('z-10', dropIndicatorPosition === 'before' ? '-top-px' : '-bottom-px')}
        />
      ) : null}

      <div
        {...dropTargetProps}
        className={cn(
          'rounded-lg border bg-appBg/40 p-3 transition',
          errorMessage ? 'border-error' : 'border-borderGray',
          isDragging && 'opacity-40',
        )}
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <span
              {...draggableProps}
              role="button"
              tabIndex={0}
              aria-label={t('stageBlock.reorder')}
              className={cn(
                'material-symbols-rounded text-textGray transition hover:text-white',
                draggableProps.draggable && 'cursor-grab active:cursor-grabbing',
              )}
            >
              drag_indicator
            </span>
            <span
              className={cn(
                'inline-flex h-5 shrink-0 items-center whitespace-nowrap rounded-md px-2 text-xs font-semibold leading-none',
                errorMessage ? 'bg-error/15 text-error' : 'bg-white/10 text-white',
              )}
            >
              {t('stageLabel', { number: stageNumber })}
            </span>
            {errorMessage ? (
              <span className="flex min-w-0 items-center gap-1 text-xs text-error">
                <span className="material-symbols-rounded text-sm" aria-hidden>
                  error
                </span>
                {errorMessage}
              </span>
            ) : (
              <span className="text-xs text-textGray">
                {t('nodeCount', { count: nodes.length })}
              </span>
            )}
          </div>
          {showRemoveStage ? (
            <button
              type="button"
              aria-label={t('stageBlock.remove')}
              onClick={(event) => {
                event.stopPropagation();
                onRemoveStage();
              }}
              className="flex size-7 items-center justify-center rounded-md text-textGray transition  hover:text-white"
            >
              <span className="material-symbols-rounded text-lg">delete</span>
            </button>
          ) : null}
        </div>

        <div className="mt-3 grid gap-2.5 sm:grid-cols-3">
          {nodes.map((node) => (
            <FlowNodeCard
              key={node.clientId}
              node={node}
              onEdit={() => onEditNode(node.clientId)}
              onRemove={() => onRemoveNode(node.clientId)}
              {...getNodeRowProps(node)}
            />
          ))}
          <button
            type="button"
            onClick={onAddNode}
            className="flex min-h-16 items-center justify-center gap-1.5 rounded-lg border border-dashed border-borderGray text-xs font-medium text-textGray transition hover:border-primary hover:text-primary"
          >
            <span className="material-symbols-rounded text-base">add</span>
            {t('stageBlock.addNode')}
          </button>
        </div>
      </div>

      {draggedNode && nodePointerY !== null && nodeDragPreviewRect ? (
        <DragPreviewCard pointerY={nodePointerY} rect={nodeDragPreviewRect}>
          <span
            className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-primary"
            aria-hidden
          >
            drag_indicator
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-white">{draggedNode.agentName}</p>
            <p className="truncate text-xs text-textGray">{draggedNode.goal || t('node.noGoal')}</p>
          </div>
        </DragPreviewCard>
      ) : null}
    </div>
  );
}
