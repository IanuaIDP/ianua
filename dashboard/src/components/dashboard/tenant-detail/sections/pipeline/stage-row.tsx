'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DragInsertionLine } from '@/components/dashboard/shared/drag-insertion-line';
import { StageActionsMenu } from '@/components/dashboard/tenant-detail/sections/pipeline/stage-actions-menu';
import { usePipelineOptions } from '@/hooks/dashboard/use-pipeline-options';
import type { DragReorderRowProps } from '@/hooks/dashboard/use-drag-reorder';
import type { Stage, StageAction } from '@/types/pipeline';
import { cn } from '@/utils/cn';

type StageRowProps = DragReorderRowProps & {
  canUpdate: boolean;
  onActionConfirm: (stage: Stage, action: StageAction) => Promise<void> | void;
  rowNumber: number | null;
  stage: Stage;
};

export function StageRow({
  canUpdate,
  draggableProps,
  dropIndicatorPosition,
  dropTargetProps,
  isDragging,
  onActionConfirm,
  rowNumber,
  stage,
}: StageRowProps) {
  const t = useTranslations('dashboard.pipelines.stage');
  const { stageKindDescription, stageKindLabel } = usePipelineOptions();
  return (
    <div {...dropTargetProps} className="relative">
      {dropIndicatorPosition ? (
        <DragInsertionLine
          className={cn('z-10', dropIndicatorPosition === 'before' ? '-top-px' : '-bottom-px')}
        />
      ) : null}

      <div
        {...draggableProps}
        className={cn(
          'flex items-center gap-3 px-4 py-3 transition',
          draggableProps.draggable && 'cursor-grab active:cursor-grabbing',
          isDragging && 'opacity-40',
        )}
      >
        {stage.isMandatory ? (
          <span
            className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-borderGray"
            aria-hidden
          >
            lock
          </span>
        ) : (
          <span
            aria-hidden
            className={cn(
              'material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-textGray transition',
              !canUpdate && 'opacity-50',
            )}
          >
            drag_indicator
          </span>
        )}

        {rowNumber !== null ? (
          <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-white/10 text-[10px] font-semibold text-white">
            {rowNumber}
          </span>
        ) : null}

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-semibold text-white">
              {stageKindLabel(stage.kind)}
            </span>
            {stage.isMandatory ? (
              <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-white/10 px-1.5 text-[10px] font-medium leading-none text-white">
                {t('default')}
              </span>
            ) : null}
          </div>
          <p className="mt-0.5 truncate text-xs text-textGray">
            {stageKindDescription(stage.kind)}
          </p>
        </div>

        {!stage.isMandatory ? <DashboardStatusBadge status={stage.status} /> : null}

        <div className="w-6 shrink-0 text-right">
          {!stage.isMandatory && canUpdate ? (
            <StageActionsMenu stage={stage} onActionConfirm={onActionConfirm} />
          ) : null}
        </div>
      </div>
    </div>
  );
}
