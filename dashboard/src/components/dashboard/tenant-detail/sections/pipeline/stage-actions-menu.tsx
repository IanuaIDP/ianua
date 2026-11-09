'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useStageActionModalContent } from '@/hooks/dashboard/use-pipeline-action-modal-content';
import { usePipelineOptions } from '@/hooks/dashboard/use-pipeline-options';
import { getApiErrorMessage } from '@/lib/api';
import type { Stage, StageAction } from '@/types/pipeline';

type StageActionsMenuProps = {
  onActionConfirm: (stage: Stage, action: StageAction) => Promise<void> | void;
  stage: Stage;
};

export function StageActionsMenu({ onActionConfirm, stage }: StageActionsMenuProps) {
  const t = useTranslations('dashboard.pipelines');
  const modalContentByAction = useStageActionModalContent();
  const { stageKindLabel } = usePipelineOptions();
  const availableActions: StageAction[] =
    stage.status === 'Enabled' ? ['Disable', 'Delete'] : ['Enable', 'Delete'];

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={t('stage.openActions', { stage: stageKindLabel(stage.kind) })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.stageUpdateFailed'))}
      getActionSuccessMessage={(action) => t(`stageActionSuccess.${action}`)}
      modalContentByAction={modalContentByAction}
      onActionConfirm={(action) => onActionConfirm(stage, action)}
    />
  );
}
