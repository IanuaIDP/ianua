import { useTranslations } from 'next-intl';

import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Flow, FlowAction } from '@/types/flow';

/** The confirmation dialogs of the flow actions, worded in the current language. */
export function useFlowText() {
  const t = useTranslations('dashboard.flows.actionModals');

  function actionModalContent(
    flow: Flow,
  ): Partial<Record<FlowAction, DashboardActionModalContent>> {
    return {
      Cancel: {
        title: t('Cancel.title'),
        description: t('Cancel.description'),
        primaryActionLabel: t('Cancel.submit'),
        secondaryActionLabel: t('Cancel.keep'),
        warningTone: 'caution',
      },
      Delete: {
        title: t('Delete.title'),
        description: t('Delete.description', { name: flow.name }),
        primaryActionLabel: t('Delete.submit'),
        warningTone: 'danger',
      },
    };
  }

  return { actionModalContent };
}
