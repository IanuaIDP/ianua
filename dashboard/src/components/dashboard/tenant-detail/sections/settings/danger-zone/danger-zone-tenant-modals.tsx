'use client';

import { useTranslations } from 'next-intl';

import { DeleteEntityModal } from '@/components/dashboard/shared/delete-entity-modal';
import { SuspendEntityModal } from '@/components/dashboard/shared/suspend-entity-modal';
import type { TenantLifecycleActions } from '@/hooks/tenants/use-tenant-lifecycle-actions';
import {
  ARCHIVE_TENANT_WARNING_IDS,
  DELETE_TENANT_REMOVED_IDS,
  SUSPEND_TENANT_WARNING_IDS,
} from '@/constants/tenant';

type DangerZoneTenantModalsProps = {
  archive: TenantLifecycleActions['archive'];
  delete: TenantLifecycleActions['delete'];
  suspend: TenantLifecycleActions['suspend'];
  tenantName: string;
};

export function DangerZoneTenantModals({
  archive,
  delete: deleteAction,
  suspend,
  tenantName,
}: DangerZoneTenantModalsProps) {
  const t = useTranslations('dashboard.tenants.dangerZone');

  return (
    <>
      <SuspendEntityModal
        open={suspend.isModalOpen}
        onClose={suspend.closeModal}
        onConfirm={() => suspend.submit()}
        confirmationValue={suspend.confirmationValue}
        onConfirmationChange={suspend.setConfirmationValue}
        entityName={tenantName}
        isSubmitting={suspend.isSubmitting}
        title={t('suspendModal.title')}
        description={t('suspendModal.description')}
        warningTitle={t('suspendModal.warningTitle')}
        warningItems={SUSPEND_TENANT_WARNING_IDS.map((id) => t(`suspendModal.items.${id}`))}
        primaryActionLabel={t('suspendModal.primary')}
      />

      <SuspendEntityModal
        open={archive.isModalOpen}
        onClose={archive.closeModal}
        onConfirm={() => archive.submit()}
        confirmationValue={archive.confirmationValue}
        onConfirmationChange={archive.setConfirmationValue}
        entityName={tenantName}
        isSubmitting={archive.isSubmitting}
        title={t('archiveModal.title')}
        description={t('archiveModal.description')}
        warningTitle={t('archiveModal.warningTitle')}
        warningItems={ARCHIVE_TENANT_WARNING_IDS.map((id) => t(`archiveModal.items.${id}`))}
        primaryActionLabel={t('archiveModal.primary')}
      />

      <DeleteEntityModal
        open={deleteAction.isModalOpen}
        onClose={deleteAction.closeModal}
        onConfirm={() => deleteAction.submit()}
        confirmationValue={deleteAction.confirmationValue}
        onConfirmationChange={deleteAction.setConfirmationValue}
        entityName={tenantName}
        isSubmitting={deleteAction.isSubmitting}
        title={t('deleteModal.title')}
        description={t('deleteModal.description')}
        warningTitle={t('deleteModal.warningTitle')}
        removeItems={DELETE_TENANT_REMOVED_IDS.map((id) => t(`deleteModal.items.${id}`))}
        primaryActionLabel={t('deleteModal.primary')}
      />
    </>
  );
}
