'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useLocale, useTranslations } from 'next-intl';

import { MemberCreatedModal } from '@/components/dashboard/shared/member-created-modal';
import { DisableScimModal } from '@/components/dashboard/tenant-detail/sections/connections/disable-scim-modal';
import { ScimSettingsForm } from '@/components/dashboard/tenant-detail/sections/connections/scim-settings-form';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  disableTenantScim,
  enableTenantScim,
  getApiErrorMessage,
  getTenantScimStatus,
  rotateTenantScimToken,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';

function scimStatusQueryKey(orgSlug: string | undefined, tenantSlug: string) {
  return ['tenant-scim-status', orgSlug, tenantSlug];
}

export function ScimProvisioningCard() {
  const t = useTranslations('dashboard.connections.scim');
  const tErrors = useTranslations('common.errors');
  const locale = useLocale();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canConfigureScim = hasPermission('Scim', 'Configure');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isDisableModalOpen, setIsDisableModalOpen] = useState(false);
  const [isRotateModalOpen, setIsRotateModalOpen] = useState(false);
  const [bearerToken, setBearerToken] = useState<string | null>(null);

  const statusQueryKey = scimStatusQueryKey(orgSlug, tenantSlug);
  const { data: scimStatus, error: scimStatusError } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantScimStatus(orgSlug ?? '', tenantSlug),
    queryKey: statusQueryKey,
  });
  const isScimEnabled = scimStatus?.enabled ?? false;
  const scimStatusErrorMessage = deriveErrorMessage([
    scimStatusError,
    getApiErrorMessage(scimStatusError, t('loadFailed')),
  ]);

  const { isPending: isEnablingScim, mutate: submitEnableScim } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return enableTenantScim(orgSlug, tenantSlug);
    },
    onSuccess: async (token) => {
      await queryClient.invalidateQueries({ queryKey: statusQueryKey });
      setBearerToken(token);
      showNotification({ message: t('toasts.enabled'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.enableFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isRotatingScimToken, mutate: submitRotateScimToken } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return rotateTenantScimToken(orgSlug, tenantSlug);
    },
    onSuccess: async (token) => {
      setIsRotateModalOpen(false);
      setBearerToken(token);
      showNotification({ message: t('toasts.rotated'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.rotateFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isDisablingScim, mutate: submitDisableScim } = useMutation({
    mutationFn: () => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return disableTenantScim(orgSlug, tenantSlug);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: statusQueryKey });
      setIsDisableModalOpen(false);
      showNotification({ message: t('toasts.disabled'), type: 'success' });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.disableFailed')),
        type: 'error',
      });
    },
  });

  return (
    <>
      <section className="mx-auto flex w-full max-w-360 flex-col gap-4 rounded-lg border border-borderGray bg-cardBg p-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-bold leading-tight text-white">{t('title')}</h2>
            <p className="mt-2.5 text-xs font-medium text-textGray">{t('description')}</p>
          </div>

          {isScimEnabled ? (
            <div className="flex items-center gap-2.5 sm:self-start">
              {canConfigureScim ? (
                <Button
                  type="button"
                  variant="outline"
                  isLoading={isRotatingScimToken}
                  onClick={() => setIsRotateModalOpen(true)}
                  className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
                >
                  {t('rotate')}
                </Button>
              ) : null}
              <Button
                type="button"
                variant="outline"
                disabled={!canConfigureScim}
                isLoading={isDisablingScim}
                onClick={() => setIsDisableModalOpen(true)}
                className="w-auto border-error px-4 py-1.5 text-sm font-medium tracking-normal text-error hover:bg-error/10"
              >
                {t('disable')}
              </Button>
            </div>
          ) : (
            <Button
              type="button"
              disabled={!canConfigureScim || !scimStatus}
              isLoading={isEnablingScim}
              onClick={() => submitEnableScim()}
              className="w-auto bg-focus px-4 py-1.5 text-sm font-medium tracking-normal text-white hover:bg-hoverBgPurple sm:self-start"
            >
              {t('enable')}
            </Button>
          )}
        </div>

        {scimStatusErrorMessage ? (
          <p className="text-xs font-medium text-error">{scimStatusErrorMessage}</p>
        ) : null}

        {isScimEnabled && scimStatus && orgSlug ? (
          <div className="grid gap-6 border-t border-borderGray pt-4 lg:grid-cols-2">
            <div className="flex flex-col gap-3 text-xs font-medium text-textGray">
              <div>
                <p className="text-sm text-white">{t('baseUrl')}</p>
                <p className="mt-1">{t('baseUrlHint')}</p>
                <code className="mt-1 block break-all rounded-md bg-primary/15 px-2 py-1.5 text-white">
                  {scimStatus.scimPath}
                </code>
              </div>
              <div>
                <p className="text-sm text-white">{t('lastContact')}</p>
                <p className="mt-1">
                  {scimStatus.lastSyncAt
                    ? new Date(scimStatus.lastSyncAt).toLocaleString(locale)
                    : t('notConnected')}
                </p>
              </div>
            </div>

            {scimStatus.settings ? (
              <ScimSettingsForm
                key={JSON.stringify(scimStatus.settings)}
                canConfigure={canConfigureScim}
                initialSettings={scimStatus.settings}
                orgSlug={orgSlug}
                statusQueryKey={statusQueryKey}
                tenantSlug={tenantSlug}
              />
            ) : null}
          </div>
        ) : null}
      </section>

      <DisableScimModal
        isSubmitting={isDisablingScim}
        open={isDisableModalOpen}
        onClose={() => setIsDisableModalOpen(false)}
        onConfirm={() => submitDisableScim()}
      />
      <Modal
        open={isRotateModalOpen}
        onClose={() => {
          if (!isRotatingScimToken) {
            setIsRotateModalOpen(false);
          }
        }}
        title={t('rotateConfirm.title')}
        description={t('rotateConfirm.description')}
        showCloseButton={false}
        primaryActionLabel={t('rotate')}
        onPrimaryAction={() => submitRotateScimToken()}
        isPrimaryActionLoading={isRotatingScimToken}
        isPrimaryActionDisabled={isRotatingScimToken}
      >
        {null}
      </Modal>
      <MemberCreatedModal
        open={Boolean(bearerToken)}
        title={t('enabledTitle')}
        description={t('enabledDescription')}
        fields={[
          {
            action: canConfigureScim
              ? {
                  icon: 'autorenew',
                  isLoading: isRotatingScimToken,
                  label: t('rotate'),
                  onClick: () => submitRotateScimToken(),
                }
              : undefined,
            label: t('bearerToken'),
            tooltipSide: 'left',
            value: bearerToken ?? '',
          },
        ]}
        onClose={() => setBearerToken(null)}
      />
    </>
  );
}
