'use client';

import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import type { UnsavedChangesGuard } from '@/hooks/dashboard/use-unsaved-changes-guard';

export function UnsavedChangesModal({ guard }: { guard: UnsavedChangesGuard }) {
  const t = useTranslations('dashboard.unsavedChanges');

  return (
    <Modal
      open={guard.pendingHref !== null}
      onClose={guard.stay}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('leave')}
      onPrimaryAction={guard.confirmLeave}
      secondaryActionLabel={t('stay')}
    >
      {null}
    </Modal>
  );
}
