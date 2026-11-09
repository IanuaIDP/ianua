import { useTranslations } from 'next-intl';

import type { DashboardActionModalContent } from '@/types/dashboard';
import type { StreamAction } from '@/types/stream';

/** The confirmation dialogs of the signal actions, worded in the current language. */
export function useStreamActionModalContent(): Partial<
  Record<StreamAction, DashboardActionModalContent>
> {
  const t = useTranslations('dashboard.streams.actionModals');

  return {
    Pause: {
      title: t('Pause.title'),
      description: t('Pause.description'),
      primaryActionLabel: t('Pause.submit'),
    },
    Resume: {
      title: t('Resume.title'),
      description: t('Resume.description'),
      primaryActionLabel: t('Resume.submit'),
    },
    Disable: {
      title: t('Disable.title'),
      description: t('Disable.description'),
      primaryActionLabel: t('Disable.submit'),
      confirmationPlaceholder: 'DISABLE',
      confirmationValue: 'DISABLE',
      warningNote: t('Disable.warning'),
      warningTone: 'caution',
    },
    Delete: {
      title: t('Delete.title'),
      description: t('Delete.description'),
      primaryActionLabel: t('Delete.submit'),
      confirmationPlaceholder: 'DELETE',
      confirmationValue: 'DELETE',
    },
  };
}
