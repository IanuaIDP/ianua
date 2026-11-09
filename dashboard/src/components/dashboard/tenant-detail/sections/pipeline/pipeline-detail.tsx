'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ActionConfirmModal } from '@/components/dashboard/shared/action-confirm-modal';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DragInsertionLine } from '@/components/dashboard/shared/drag-insertion-line';
import { DragPreviewCard } from '@/components/dashboard/shared/drag-preview-card';
import { AddStageModal } from '@/components/dashboard/tenant-detail/sections/pipeline/add-stage-modal';
import { StageRow } from '@/components/dashboard/tenant-detail/sections/pipeline/stage-row';
import { useNotification } from '@/components/ui/notifications';
import { reorderById, useDragReorder } from '@/hooks/dashboard/use-drag-reorder';
import { usePipelineActionModalContent } from '@/hooks/dashboard/use-pipeline-action-modal-content';
import { usePipelineOptions } from '@/hooks/dashboard/use-pipeline-options';
import type { DragReorderPosition } from '@/hooks/dashboard/use-drag-reorder';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  addPipelineStage,
  deriveErrorMessage,
  executePipelineAction,
  executeStageAction,
  getApiErrorMessage,
  getTenantPipeline,
  reorderPipelineStages,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { AddableStagePayload, PipelineAction, Stage, StageAction } from '@/types/pipeline';

type PipelineDetailProps = {
  pipelineId: string;
};

export function PipelineDetail({ pipelineId }: PipelineDetailProps) {
  const t = useTranslations('dashboard.pipelines.detail');
  const tPipelines = useTranslations('dashboard.pipelines');
  const tActions = useTranslations('dashboard.actions.labels');
  const tErrors = useTranslations('common.errors');
  const pipelineActionModalContent = usePipelineActionModalContent();
  const { stageKindDescription, stageKindLabel } = usePipelineOptions();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canUpdatePipeline = hasPermission('Pipeline', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isAddStageOpen, setIsAddStageOpen] = useState(false);
  const [pendingPipelineAction, setPendingPipelineAction] = useState<PipelineAction | null>(null);
  const [confirmationValue, setConfirmationValue] = useState('');

  const {
    data: pipeline,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPipeline(orgSlug ?? '', tenantSlug, pipelineId),
    queryKey: ['tenant-pipeline', orgSlug, tenantSlug, pipelineId],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  async function invalidatePipeline() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-pipeline', orgSlug, tenantSlug, pipelineId],
    });
    await queryClient.invalidateQueries({ queryKey: ['tenant-pipelines', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  const { isPending: isSubmittingPipelineAction, mutate: submitPendingPipelineAction } =
    useMutation({
      mutationFn: () => {
        if (!orgSlug || !pendingPipelineAction) {
          throw new Error('Nothing to confirm.');
        }

        return executePipelineAction(orgSlug, tenantSlug, pipelineId, pendingPipelineAction);
      },
      onSuccess: async () => {
        const action = pendingPipelineAction;
        setPendingPipelineAction(null);
        setConfirmationValue('');
        showNotification({
          message:
            action === 'Activate'
              ? tPipelines('actionSuccess.Activate')
              : tPipelines('actionSuccess.Disable'),
          type: 'success',
        });
        await invalidatePipeline();
      },
      onError: (mutationError) => {
        setPendingPipelineAction(null);
        setConfirmationValue('');
        showNotification({
          message: getApiErrorMessage(mutationError, tPipelines('toasts.updateFailed')),
          type: 'error',
        });
      },
    });

  const { isPending: isAddingStage, mutate: submitAddStage } = useMutation({
    mutationFn: (payload: AddableStagePayload) => {
      if (!orgSlug || !pipeline) {
        throw new Error(tErrors('organizationMissing'));
      }

      return addPipelineStage(orgSlug, tenantSlug, pipelineId, {
        ...payload,
        position: pipeline.stages.length,
      });
    },
    onSuccess: async () => {
      setIsAddStageOpen(false);
      showNotification({ message: t('stageAdded'), type: 'success' });
      await invalidatePipeline();
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('stageAddFailed')),
        type: 'error',
      });
    },
  });

  async function handleStageAction(stage: Stage, action: StageAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeStageAction(orgSlug, tenantSlug, pipelineId, stage, action);
    await invalidatePipeline();
  }

  const customStages = (pipeline?.stages ?? []).filter((stage) => !stage.isMandatory);

  async function handleStageDrop(
    fromStageId: string,
    targetStageId: string,
    position: DragReorderPosition,
  ) {
    if (!orgSlug || !pipeline) {
      return;
    }

    const reorderedCustom = reorderById(
      customStages,
      (stage) => stage.id,
      fromStageId,
      targetStageId,
      position,
    );

    if (reorderedCustom === customStages) {
      return;
    }

    const mandatoryStages = pipeline.stages.filter((stage) => stage.isMandatory);
    const stageIds = [...mandatoryStages, ...reorderedCustom].map((stage) => stage.id);

    try {
      await reorderPipelineStages(orgSlug, tenantSlug, pipelineId, stageIds);
      await invalidatePipeline();
    } catch (reorderError) {
      showNotification({
        message: getApiErrorMessage(reorderError, t('reorderFailed')),
        type: 'error',
      });
    }
  }

  const {
    dragPreviewRect,
    draggedItem: draggedStage,
    getRowProps,
    isDropAfterLastItem: isDropAfterLastStage,
    pointerY,
  } = useDragReorder<Stage>({
    getId: (stage) => stage.id,
    isDraggable: (stage) => canUpdatePipeline && !stage.isMandatory,
    isDropTarget: (stage) => !stage.isMandatory,
    items: pipeline?.stages ?? [],
    onDrop: handleStageDrop,
  });

  const primaryPipelineAction: PipelineAction | null = pipeline
    ? pipeline.status === 'Active'
      ? 'Disable'
      : 'Activate'
    : null;

  const draggedStageRowNumber = draggedStage
    ? (pipeline?.stages.findIndex((stage) => stage.id === draggedStage.id) ?? -1) + 1
    : null;

  return (
    <div className="flex flex-col gap-4">
      {errorMessage ? (
        <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {errorMessage}
        </p>
      ) : null}

      {isLoading ? (
        <DashboardDataCard description={t('stagesDescription')} title={t('stages')}>
          <div className="flex items-center gap-3 bg-borderGray px-4 py-2.5 text-xs font-extrabold text-textGray">
            <span className="flex-1">{t('stages')}</span>
          </div>
          <div className="flex h-36 items-center justify-center px-4 text-center text-xs font-medium text-textGray">
            {t('loading')}
          </div>
        </DashboardDataCard>
      ) : pipeline ? (
        <>
          <div className="mx-auto w-full max-w-360 rounded-lg border border-borderGray bg-cardBg p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2">
                <h1 className="truncate text-base font-bold text-white">{pipeline.name}</h1>
              </div>
              {canUpdatePipeline && primaryPipelineAction ? (
                <button
                  type="button"
                  onClick={() => setPendingPipelineAction(primaryPipelineAction)}
                  className={
                    primaryPipelineAction === 'Activate'
                      ? 'inline-flex h-8 items-center gap-1.5 rounded-lg bg-focus px-3.5 text-sm font-medium text-white transition hover:bg-focus/90'
                      : 'inline-flex h-8 items-center gap-1.5 rounded-lg border border-error bg-transparent px-3.5 text-sm font-medium text-error transition hover:bg-error/10'
                  }
                >
                  <span className="material-symbols-rounded text-base!" aria-hidden>
                    {primaryPipelineAction === 'Activate' ? 'play_circle' : 'cancel'}
                  </span>
                  {tActions(primaryPipelineAction)}
                </button>
              ) : null}
            </div>

            <div className="mt-3 grid grid-cols-1 overflow-hidden rounded-[10px] border border-borderGray sm:grid-cols-2 lg:grid-cols-4">
              <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-r lg:border-b-0">
                <span className="text-[10px] text-textGray">{t('status')}</span>
                <DashboardStatusBadge status={pipeline.status} />
              </div>
              <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 lg:border-b-0 lg:border-r">
                <span className="text-[10px] text-textGray">{t('totalStages')}</span>
                <span className="text-xs text-white">{pipeline.stages.length}</span>
              </div>
              <div className="flex flex-col items-start justify-center gap-1.5 border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                <span className="text-[10px] text-textGray">{t('defaultStages')}</span>
                <span className="text-xs text-white">
                  {pipeline.stages.length - customStages.length}
                </span>
              </div>
              <div className="flex flex-col items-start justify-center gap-1.5 px-4 py-3">
                <span className="text-[10px] text-textGray">{t('customStages')}</span>
                <span className="text-xs text-white">{customStages.length}</span>
              </div>
            </div>
          </div>

          <div className="relative">
            <DashboardDataCard
              isSecondaryActionDisabled={pipeline.status === 'Active'}
              secondaryActionLabel={canUpdatePipeline ? t('addStage') : undefined}
              secondaryActionTooltip={t('addStageTooltip')}
              description={t('stagesDescription')}
              title={t('stages')}
              onSecondaryActionClick={canUpdatePipeline ? () => setIsAddStageOpen(true) : undefined}
            >
              <div className="flex items-center gap-3 bg-borderGray px-4 py-2.5 text-xs font-extrabold text-textGray">
                <span className="flex-1">{t('stages')}</span>
              </div>
              <div className="divide-y divide-borderGray">
                {pipeline.stages.map((stage, index) => (
                  <StageRow
                    key={stage.id}
                    canUpdate={canUpdatePipeline}
                    rowNumber={index + 1}
                    stage={stage}
                    onActionConfirm={handleStageAction}
                    {...getRowProps(stage)}
                  />
                ))}
              </div>
            </DashboardDataCard>

            {isDropAfterLastStage ? <DragInsertionLine className="bottom-0 z-20" /> : null}
          </div>
        </>
      ) : null}

      {draggedStage && pointerY !== null && dragPreviewRect ? (
        <DragPreviewCard pointerY={pointerY} rect={dragPreviewRect}>
          <span
            className="material-symbols-rounded flex size-5 shrink-0 items-center justify-center text-primary"
            aria-hidden
          >
            drag_indicator
          </span>
          {draggedStageRowNumber !== null ? (
            <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-white/10 text-[10px] font-semibold text-white">
              {draggedStageRowNumber}
            </span>
          ) : null}
          <div className="min-w-0 flex-1">
            <span className="truncate text-sm font-semibold text-white">
              {stageKindLabel(draggedStage.kind)}
            </span>
            <p className="mt-0.5 truncate text-xs text-textGray">
              {stageKindDescription(draggedStage.kind)}
            </p>
          </div>
          <DashboardStatusBadge status={draggedStage.status} />
        </DragPreviewCard>
      ) : null}

      <AddStageModal
        existingKinds={pipeline?.stages.map((stage) => stage.kind) ?? []}
        isSubmitting={isAddingStage}
        open={isAddStageOpen}
        orgSlug={orgSlug}
        tenantSlug={tenantSlug}
        onClose={() => setIsAddStageOpen(false)}
        onSubmit={submitAddStage}
      />

      <ActionConfirmModal
        confirmationValue={confirmationValue}
        content={pendingPipelineAction ? pipelineActionModalContent[pendingPipelineAction] : null}
        isSubmitting={isSubmittingPipelineAction}
        onClose={() => {
          setPendingPipelineAction(null);
          setConfirmationValue('');
        }}
        onConfirm={() => submitPendingPipelineAction()}
        onConfirmationChange={setConfirmationValue}
      />
    </div>
  );
}
