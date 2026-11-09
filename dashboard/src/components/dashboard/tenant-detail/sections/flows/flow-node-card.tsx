'use client';

import type { KeyboardEvent } from 'react';
import { useTranslations } from 'next-intl';

import { DragInsertionLine } from '@/components/dashboard/shared/drag-insertion-line';
import { Tooltip } from '@/components/ui/tooltip';
import type { DragReorderRowProps } from '@/hooks/dashboard/use-drag-reorder';
import { useToolOptions } from '@/hooks/dashboard/use-tool-options';
import type { FlowNodeDraft } from '@/types/flow-builder';
import { cn } from '@/utils/cn';

type FlowNodeCardProps = DragReorderRowProps & {
  node: FlowNodeDraft;
  onEdit: () => void;
  onRemove: () => void;
};

const chipClassName =
  'inline-flex shrink-0 items-center gap-1 rounded-md bg-surfaceChip px-2 py-1 text-xs font-medium text-white hover:bg-borderGray';

export function FlowNodeCard({
  draggableProps,
  dropIndicatorAxis,
  dropIndicatorPosition,
  dropTargetProps,
  isDragging,
  node,
  onEdit,
  onRemove,
}: FlowNodeCardProps) {
  const t = useTranslations('dashboard.flows.node');
  const { actionClassLabel } = useToolOptions();
  const purposeLabel = node.purpose.map(actionClassLabel).join(', ');
  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onEdit();
    }
  }

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onEdit}
      onKeyDown={handleKeyDown}
      {...dropTargetProps}
      className={cn(
        'relative flex cursor-pointer flex-col gap-2 rounded-lg border border-borderGray bg-appBg/40 p-3 text-left transition hover:border-primary hover:shadow-primary-soft',
        isDragging && 'opacity-40',
      )}
    >
      {dropIndicatorAxis && dropIndicatorPosition ? (
        <DragInsertionLine
          orientation={dropIndicatorAxis === 'horizontal' ? 'vertical' : 'horizontal'}
          className={cn(
            'z-10',
            dropIndicatorAxis === 'horizontal'
              ? dropIndicatorPosition === 'before'
                ? '-left-1.5'
                : '-right-1.5'
              : dropIndicatorPosition === 'before'
                ? '-top-1.5'
                : '-bottom-1.5',
          )}
        />
      ) : null}

      <div className="flex items-start justify-between gap-2">
        <p className="truncate text-sm font-semibold text-white">{node.agentName}</p>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            aria-label={t('remove')}
            onClick={(event) => {
              event.stopPropagation();
              onRemove();
            }}
            className="flex size-7 items-center justify-center rounded-md text-textGray transition hover:text-white"
          >
            <span className="material-symbols-rounded text-lg">delete</span>
          </button>
          <span
            {...draggableProps}
            role="button"
            tabIndex={0}
            aria-label={t('reorder')}
            onClick={(event) => event.stopPropagation()}
            onKeyDown={(event) => event.stopPropagation()}
            className={cn(
              'flex size-7 items-center justify-center text-textGray transition hover:text-white',
              draggableProps.draggable && 'cursor-grab active:cursor-grabbing',
            )}
          >
            <span className="material-symbols-rounded text-lg" aria-hidden>
              drag_indicator
            </span>
          </span>
        </div>
      </div>

      <p className="truncate text-xs text-textGray">{node.goal || t('noGoal')}</p>

      <div className="flex flex-wrap items-center gap-1.5">
        {node.purpose.length > 0 ? (
          <Tooltip title={t('actionClasses')} content={purposeLabel} side="bottom-right">
            <span className={cn(chipClassName, 'max-w-32')}>
              <span className="truncate">{purposeLabel}</span>
            </span>
          </Tooltip>
        ) : null}
        <span className={chipClassName}>≤{node.maxSteps}</span>
        {node.providerModel ? (
          <span className={chipClassName}>
            <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
              neurology
            </span>
            {node.providerModel}
          </span>
        ) : null}
        {node.toolNames.length > 0 ? (
          <Tooltip title={t('tools')} content={node.toolNames.join(', ')} side="bottom-left">
            <span className={chipClassName}>
              <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
                handyman
              </span>
              {node.toolNames.length}
            </span>
          </Tooltip>
        ) : null}
        {node.approvalClasses.length > 0 ? (
          <Tooltip
            title={t('approvals')}
            content={node.approvalClasses.join(', ')}
            side="bottom-left"
          >
            <span className={chipClassName}>
              <span className="material-symbols-rounded text-sm! text-textGray mt-px" aria-hidden>
                assignment_turned_in
              </span>
              {node.approvalClasses.length}
            </span>
          </Tooltip>
        ) : null}
      </div>
    </div>
  );
}
