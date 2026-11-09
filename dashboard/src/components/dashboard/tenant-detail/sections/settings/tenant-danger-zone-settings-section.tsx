'use client';

import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { DangerZoneActionRow } from '@/components/dashboard/tenant-detail/sections/settings/danger-zone/danger-zone-action-row';
import { DangerZoneOrgModals } from '@/components/dashboard/tenant-detail/sections/settings/danger-zone/danger-zone-org-modals';
import { DangerZoneTenantModals } from '@/components/dashboard/tenant-detail/sections/settings/danger-zone/danger-zone-tenant-modals';
import { useTenantLifecycleActions } from '@/hooks/tenants/use-tenant-lifecycle-actions';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';

export function TenantDangerZoneSettingsSection() {
  const t = useTranslations('dashboard.tenants.dangerZone');
  const { hasPermission } = useTenantPermissions();
  const canManageDangerZone = hasPermission('TenantSettings', 'Update');
  const {
    archive,
    canRestoreAccess,
    delete: deleteAction,
    isDangerZoneButtonDisabled,
    isStatusArchived,
    isTenantView,
    restore,
    suspend,
    tenantName,
  } = useTenantLifecycleActions();

  if (!canManageDangerZone) {
    return null;
  }

  return (
    <SettingsCard title={t('title')} description={t('description')}>
      <div className="flex flex-col items-start overflow-hidden rounded-lg border border-borderGray">
        {!isStatusArchived ? (
          <DangerZoneActionRow
            label={canRestoreAccess ? t('restore.label') : t('suspend.label')}
            description={canRestoreAccess ? t('restore.description') : t('suspend.description')}
            buttonLabel={canRestoreAccess ? t('restore.button') : t('suspend.button')}
            tone={canRestoreAccess ? 'neutral' : 'warning'}
            onClick={canRestoreAccess ? restore.openModal : suspend.openModal}
            disabled={isDangerZoneButtonDisabled(
              canRestoreAccess ? restore.isSubmitting : suspend.isSubmitting,
            )}
          />
        ) : null}

        {!isStatusArchived ? (
          <DangerZoneActionRow
            label={t('archive.label')}
            description={t('archive.description')}
            buttonLabel={t('archive.button')}
            tone="warning"
            onClick={archive.openModal}
            disabled={isDangerZoneButtonDisabled(archive.isSubmitting)}
          />
        ) : null}

        <DangerZoneActionRow
          label={t('delete.label')}
          description={t('delete.description')}
          buttonLabel={t('delete.button')}
          tone="danger"
          isLast
          onClick={deleteAction.openModal}
          disabled={isDangerZoneButtonDisabled(deleteAction.isSubmitting)}
        />
      </div>

      {isTenantView ? (
        <DangerZoneTenantModals
          archive={archive}
          delete={deleteAction}
          suspend={suspend}
          tenantName={tenantName}
        />
      ) : (
        <DangerZoneOrgModals
          archive={archive}
          delete={deleteAction}
          restore={restore}
          suspend={suspend}
        />
      )}
    </SettingsCard>
  );
}
