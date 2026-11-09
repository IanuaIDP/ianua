import { useTranslations } from 'next-intl';

import type { DashboardActionModalContent } from '@/types/dashboard';
import type { PipelineAction, StageAction } from '@/types/pipeline';

/** The confirmation dialogs of the pipeline actions, worded in the current language. */
export function usePipelineActionModalContent(): Partial<
  Record<PipelineAction, DashboardActionModalContent>
> {
  const t = useTranslations('dashboard.pipelines.actionModals');

  return {
    Activate: {
      title: t('Activate.title'),
      description: t('Activate.description'),
      primaryActionLabel: t('Activate.submit'),
    },
    Disable: {
      title: t('Disable.title'),
      description: t('Disable.description'),
      primaryActionLabel: t('Disable.submit'),
      warningNote: t('Disable.warning'),
      warningTone: 'danger',
    },
    Delete: {
      title: t('Delete.title'),
      description: t('Delete.description'),
      primaryActionLabel: t('Delete.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
      warningNote: t('Delete.warning'),
      warningTone: 'caution',
    },
  };
}

/** The confirmation dialogs of the stage actions, worded in the current language. */
export function useStageActionModalContent(): Partial<
  Record<StageAction, DashboardActionModalContent>
> {
  const t = useTranslations('dashboard.pipelines.stageActionModals');

  return {
    Enable: {
      title: t('Enable.title'),
      description: t('Enable.description'),
      primaryActionLabel: t('Enable.submit'),
    },
    Disable: {
      title: t('Disable.title'),
      description: t('Disable.description'),
      primaryActionLabel: t('Disable.submit'),
    },
    Delete: {
      title: t('Delete.title'),
      description: t('Delete.description'),
      primaryActionLabel: t('Delete.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
      warningNote: t('Delete.warning'),
      warningTone: 'caution',
    },
  };
}
