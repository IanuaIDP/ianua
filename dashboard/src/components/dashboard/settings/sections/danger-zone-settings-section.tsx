'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { SuspendEntityModal } from '@/components/dashboard/shared/suspend-entity-modal';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { closeOrganization, getApiErrorMessage, suspendOrganization } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import { useOrganizationStore } from '@/store/organization-store';
import { cn } from '@/utils/cn';

import { CloseOrganizationModal } from './danger-zone/close-organization-modal';
import { SettingsCard } from '../settings-card';

const SUSPEND_WARNING_IDS = ['access', 'sessions', 'data', 'reactivate'] as const;

export function DangerZoneSettingsSection() {
  const t = useTranslations('dashboard.settings.dangerZone');
  const tErrors = useTranslations('common.errors');
  const { showNotification } = useNotification();
  const { canCloseOrganization } = useOrgAccess();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const organization = useOrganizationStore((state) => state.organization);
  const clearOrganization = useOrganizationStore((state) => state.clearOrganization);
  const [closeConfirmationValue, setCloseConfirmationValue] = useState('');
  const [isCloseModalOpen, setIsCloseModalOpen] = useState(false);
  const [isSuspendModalOpen, setIsSuspendModalOpen] = useState(false);
  const [suspendConfirmationValue, setSuspendConfirmationValue] = useState('');
  const organizationName =
    organization?.displayName || organization?.name || organization?.slug || '';
  const { isPending: isSuspendingOrganization, mutate: submitSuspendOrganization } = useMutation({
    mutationFn: () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return suspendOrganization(organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('suspend.failed')),
        type: 'error',
      });
    },
    onSuccess: () => {
      clearOrganization();
      window.location.assign('/organization-suspended');
    },
  });
  const { isPending: isClosingOrganization, mutate: submitCloseOrganization } = useMutation({
    mutationFn: () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return closeOrganization(organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('close.failed')),
        type: 'error',
      });
    },
    onSuccess: () => {
      clearOrganization();
      window.location.assign('/organization-closed');
    },
  });

  function closeSuspendModal() {
    if (isSuspendingOrganization) {
      return;
    }

    setIsSuspendModalOpen(false);
    setSuspendConfirmationValue('');
  }

  function closeCloseModal() {
    if (isClosingOrganization) {
      return;
    }

    setIsCloseModalOpen(false);
    setCloseConfirmationValue('');
  }

  return (
    <>
      <SettingsCard title={t('title')} description={t('description')}>
        <div className="flex flex-col items-start overflow-hidden rounded-lg border border-borderGray">
          <div
            className={cn(
              'flex w-full flex-col items-start sm:flex-row sm:items-center sm:justify-between',
              canCloseOrganization && 'border-b border-borderGray',
            )}
          >
            <div className="px-4 py-3">
              <p className="text-sm font-bold text-white">{t('suspend.title')}</p>
              <span className="mt-2 text-xs font-medium text-textGray">{t('suspend.summary')}</span>
            </div>
            <div className="px-4 py-3">
              <Button
                type="button"
                onClick={() => setIsSuspendModalOpen(true)}
                disabled={!organization || isSuspendingOrganization || isClosingOrganization}
                className="w-auto px-4 py-1.5 font-medium tracking-normal border border-orange bg-transparent text-orange hover:bg-orange/10"
              >
                {t('suspend.button')}
              </Button>
            </div>
          </div>
          {canCloseOrganization ? (
            <div className="flex w-full flex-col items-start sm:flex-row sm:items-center sm:justify-between">
              <div className="px-4 py-3">
                <p className="text-sm font-bold text-white">{t('close.title')}</p>
                <span className="mt-2 text-xs font-medium text-textGray">{t('close.summary')}</span>
              </div>
              <div className="px-4 py-3">
                <Button
                  type="button"
                  onClick={() => setIsCloseModalOpen(true)}
                  disabled={!organization || isSuspendingOrganization || isClosingOrganization}
                  className="w-auto px-4 py-1.5 font-medium tracking-normal bg-transparent border border-error text-error hover:bg-error/10"
                >
                  {t('close.button')}
                </Button>
              </div>
            </div>
          ) : null}
        </div>
      </SettingsCard>

      <SuspendEntityModal
        open={isSuspendModalOpen}
        onClose={closeSuspendModal}
        onConfirm={() => submitSuspendOrganization()}
        confirmationValue={suspendConfirmationValue}
        onConfirmationChange={setSuspendConfirmationValue}
        entityName={organizationName}
        isSubmitting={isSuspendingOrganization}
        title={t('suspend.modalTitle')}
        description={t('suspend.modalDescription')}
        warningTitle={t('suspend.warningTitle')}
        warningItems={SUSPEND_WARNING_IDS.map((id) => t(`suspend.warnings.${id}`))}
        primaryActionLabel={t('suspend.title')}
      />

      <CloseOrganizationModal
        open={isCloseModalOpen}
        onClose={closeCloseModal}
        onConfirm={() => submitCloseOrganization()}
        confirmationValue={closeConfirmationValue}
        onConfirmationChange={setCloseConfirmationValue}
        organizationName={organizationName}
        isSubmitting={isClosingOrganization}
      />
    </>
  );
}
