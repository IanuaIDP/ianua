'use client';

import { useTenantActionModalContent } from '@/components/dashboard/tenants/tenant-actions-menu';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import type { TenantLifecycleActions } from '@/hooks/tenants/use-tenant-lifecycle-actions';
import { ConfirmationLabel } from '@/utils/confirmation-label';

type DangerZoneOrgModalsProps = {
  archive: TenantLifecycleActions['archive'];
  delete: TenantLifecycleActions['delete'];
  restore: TenantLifecycleActions['restore'];
  suspend: TenantLifecycleActions['suspend'];
};

export function DangerZoneOrgModals({
  archive,
  delete: deleteAction,
  restore,
  suspend,
}: DangerZoneOrgModalsProps) {
  const tenantActionModalContent = useTenantActionModalContent();
  const deleteForeverModalContent = tenantActionModalContent['Delete forever'];
  const deleteForeverConfirmationValue = deleteForeverModalContent.confirmationValue ?? 'DELETE';

  return (
    <>
      <Modal
        open={suspend.isModalOpen}
        onClose={suspend.closeModal}
        title={tenantActionModalContent.Suspend.title}
        description={tenantActionModalContent.Suspend.description}
        primaryActionLabel={tenantActionModalContent.Suspend.primaryActionLabel}
        onPrimaryAction={() => suspend.submit()}
        isPrimaryActionDisabled={suspend.isSubmitting}
        isPrimaryActionLoading={suspend.isSubmitting}
        showCloseButton={false}
      >
        {null}
      </Modal>

      <Modal
        open={restore.isModalOpen}
        onClose={restore.closeModal}
        title={tenantActionModalContent['Restore Access'].title}
        description={tenantActionModalContent['Restore Access'].description}
        primaryActionLabel={tenantActionModalContent['Restore Access'].primaryActionLabel}
        onPrimaryAction={() => restore.submit()}
        isPrimaryActionDisabled={restore.isSubmitting}
        isPrimaryActionLoading={restore.isSubmitting}
        showCloseButton={false}
      >
        {null}
      </Modal>

      <Modal
        open={archive.isModalOpen}
        onClose={archive.closeModal}
        title={tenantActionModalContent.Archive.title}
        description={tenantActionModalContent.Archive.description}
        primaryActionLabel={tenantActionModalContent.Archive.primaryActionLabel}
        onPrimaryAction={() => archive.submit()}
        isPrimaryActionDisabled={archive.isSubmitting}
        isPrimaryActionLoading={archive.isSubmitting}
        showCloseButton={false}
      >
        {null}
      </Modal>

      <Modal
        open={deleteAction.isModalOpen}
        onClose={deleteAction.closeModal}
        title={deleteForeverModalContent.title}
        description={deleteForeverModalContent.description}
        primaryActionLabel={deleteForeverModalContent.primaryActionLabel}
        onPrimaryAction={() => deleteAction.submit()}
        isPrimaryActionDisabled={
          deleteAction.confirmationValue !== deleteForeverConfirmationValue ||
          deleteAction.isSubmitting
        }
        isPrimaryActionLoading={deleteAction.isSubmitting}
        showCloseButton={false}
      >
        <div>
          <p className="mb-3 text-xs text-textGray">
            <ConfirmationLabel
              label={deleteForeverModalContent.confirmationLabel}
              value={deleteForeverConfirmationValue}
            />
          </p>
          <Input
            value={deleteAction.confirmationValue}
            onChange={(event) => deleteAction.setConfirmationValue(event.target.value)}
            placeholder={deleteForeverModalContent.confirmationPlaceholder}
            containerClassName="mb-0"
            className="max-w-48 bg-cardBg"
          />
        </div>
      </Modal>
    </>
  );
}
