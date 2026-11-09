'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { CloudAccountsTable } from '@/components/dashboard/settings/sections/cloud/cloud-accounts-table';
import { ConnectCloudModal } from '@/components/dashboard/settings/sections/cloud/connect-cloud-modal';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { getCloudProviderLabel } from '@/constants/cloud';
import {
  deriveErrorMessage,
  disconnectCloudAccount,
  getApiErrorMessage,
  getCloudAccounts,
  submitCloudCredential,
  verifyCloudAccount,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CloudCredentialInput } from '@/schemas/cloud-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { CloudAccount, CloudAccountAction, CloudProviderId } from '@/types/cloud-account';

type ConnectPayload = {
  payload: CloudCredentialInput;
  provider: CloudProviderId;
};

export function CloudSettingsSection() {
  const t = useTranslations('dashboard.settings.cloud');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const {
    data: cloudAccounts,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () => getCloudAccounts(organizationSlug ?? ''),
    queryKey: ['cloud-accounts', organizationSlug],
  });
  const { isPending: isConnecting, mutate: submitConnect } = useMutation({
    mutationFn: ({ payload, provider }: ConnectPayload) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return submitCloudCredential(organizationSlug, provider, payload);
    },
    onSuccess: async (account) => {
      setIsConnectModalOpen(false);
      showNotification({
        message: account.usable
          ? t('toasts.connected', { provider: getCloudProviderLabel(account.provider) })
          : (account.failureReason ??
            t('toasts.notWorking', { provider: getCloudProviderLabel(account.provider) })),
        type: account.usable ? 'success' : 'error',
      });
      await queryClient.invalidateQueries({ queryKey: ['cloud-accounts', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.connectFailed')),
        type: 'error',
      });
    },
  });

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const handleCloudAccountAction = async (account: CloudAccount, action: CloudAccountAction) => {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    if (action === 'Disconnect') {
      await disconnectCloudAccount(organizationSlug, account.provider);
    }

    if (action === 'Reverify') {
      await verifyCloudAccount(organizationSlug, account.provider);
    }

    await queryClient.invalidateQueries({ queryKey: ['cloud-accounts', organizationSlug] });
    await invalidateAuditLogQueries(queryClient, organizationSlug);
  };

  return (
    <SettingsCard
      title={t('title')}
      description={t('description')}
      className="flex max-h-[calc(100vh-5.25rem)] min-h-0 flex-col overflow-hidden"
      headerAction={
        <Button
          type="button"
          onClick={() => setIsConnectModalOpen(true)}
          className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
        >
          {t('connect')}
        </Button>
      }
    >
      <div className="-mx-4 -mb-4 flex min-h-0 flex-1 flex-col">
        {errorMessage ? (
          <p className="mt-4 px-4 text-sm font-medium text-error">{errorMessage}</p>
        ) : null}

        <CloudAccountsTable
          accounts={cloudAccounts ?? []}
          isLoading={isLoading}
          onAccountAction={handleCloudAccountAction}
        />
      </div>

      <ConnectCloudModal
        connectedProviders={(cloudAccounts ?? []).map((account) => account.provider)}
        isSubmitting={isConnecting}
        open={isConnectModalOpen}
        orgSlug={organizationSlug}
        onClose={() => setIsConnectModalOpen(false)}
        onSubmit={(provider, payload) => submitConnect({ payload, provider })}
      />
    </SettingsCard>
  );
}
