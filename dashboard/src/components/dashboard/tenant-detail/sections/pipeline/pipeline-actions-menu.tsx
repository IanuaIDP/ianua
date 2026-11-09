'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { usePipelineActionModalContent } from '@/hooks/dashboard/use-pipeline-action-modal-content';
import { getApiErrorMessage } from '@/lib/api';
import type { PipelineAction, PipelineStatus, PipelineSummary } from '@/types/pipeline';

const pipelineActionsByStatus: Record<PipelineStatus, PipelineAction[]> = {
  Active: ['Disable'],
  Disabled: ['Activate', 'Delete'],
  Draft: ['Activate', 'Delete'],
};

type PipelineActionsMenuProps = {
  canUpdate?: boolean;
  onActionConfirm: (pipeline: PipelineSummary, action: PipelineAction) => Promise<void> | void;
  pipeline: PipelineSummary;
};

export function PipelineActionsMenu({
  canUpdate = true,
  onActionConfirm,
  pipeline,
}: PipelineActionsMenuProps) {
  const t = useTranslations('dashboard.pipelines');
  const tActions = useTranslations('dashboard.actions');
  const modalContentByAction = usePipelineActionModalContent();
  const availableActions = pipelineActionsByStatus[pipeline.status].filter((action) => {
    if (!canUpdate) {
      return false;
    }

    // A pipeline a route still runs cannot be deleted — the API refuses it, and
    // offering the action only to fail is worse than not offering it.
    return action !== 'Delete' || pipeline.routeCount === 0;
  });

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: pipeline.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) => t(`actionSuccess.${action}`)}
      modalContentByAction={modalContentByAction}
      onActionConfirm={(action) => onActionConfirm(pipeline, action)}
    />
  );
}
