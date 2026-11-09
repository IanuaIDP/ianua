'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { ConnectProviderModal } from '@/components/dashboard/tenant-detail/sections/model-providers/connect-provider-modal';
import { EmbeddingModelModal } from '@/components/dashboard/tenant-detail/sections/model-providers/embedding-model-modal';
import { ProviderClearanceModal } from '@/components/dashboard/tenant-detail/sections/model-providers/provider-clearance-modal';
import { ModelProvidersTable } from '@/components/dashboard/tenant-detail/sections/model-providers/model-providers-table';
import { useNotification } from '@/components/ui/notifications';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  connectTenantModelProvider,
  deriveErrorMessage,
  executeTenantModelProviderAction,
  getApiErrorMessage,
  getTenantModelProviders,
  testTenantModelProvider,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ConnectModelProviderInput } from '@/schemas/model-provider-schemas';
import type {
  ModelProvider,
  ModelProviderAction,
  ModelProviderTestState,
} from '@/types/model-provider';

export function ModelProvidersCard() {
  const t = useTranslations('dashboard.modelProviders');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const canConnectProvider = hasPermission('Agents', 'Manage');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const [embeddingProvider, setEmbeddingProvider] = useState<ModelProvider | null>(null);
  const [clearanceProvider, setClearanceProvider] = useState<ModelProvider | null>(null);
  const [testStateByProviderId, setTestStateByProviderId] = useState<
    Record<string, ModelProviderTestState | undefined>
  >({});

  const {
    data: providers,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
  });
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { isPending: isConnectingProvider, mutate: submitConnectProvider } = useMutation({
    mutationFn: (payload: ConnectModelProviderInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return connectTenantModelProvider(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsConnectModalOpen(false);
      showNotification({ message: t('toasts.connected'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.connectFailed')),
        type: 'error',
      });
    },
  });

  async function handleTest(provider: ModelProvider) {
    if (!orgSlug) {
      return;
    }

    setTestStateByProviderId((previous) => ({ ...previous, [provider.id]: { status: 'pending' } }));

    try {
      const result = await testTenantModelProvider(orgSlug, tenantSlug, provider.id);
      setTestStateByProviderId((previous) => ({
        ...previous,
        [provider.id]: { result, status: 'success', testedAt: new Date() },
      }));
      showNotification({
        message: result.ok
          ? t('toasts.testPassed', { name: provider.name })
          : t('toasts.testFailed', { name: provider.name }),
        type: result.ok ? 'success' : 'error',
      });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
      });
    } catch (testError) {
      const message = getApiErrorMessage(testError, t('toasts.unreachable'));

      setTestStateByProviderId((previous) => ({
        ...previous,
        [provider.id]: {
          message,
          status: 'error',
          testedAt: new Date(),
        },
      }));
      showNotification({
        message: t('toasts.testFailedWithReason', { message, name: provider.name }),
        type: 'error',
      });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
      });
    }
  }

  async function handleProviderAction(provider: ModelProvider, action: ModelProviderAction) {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    await executeTenantModelProviderAction(orgSlug, tenantSlug, provider, action);
    await queryClient.invalidateQueries({
      queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
    });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={t('connect')}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={canConnectProvider ? () => setIsConnectModalOpen(true) : undefined}
      >
        <ModelProvidersTable
          isLoading={isLoading}
          providers={providers ?? []}
          testStateByProviderId={testStateByProviderId}
          onClearance={setClearanceProvider}
          onEmbeddingModel={setEmbeddingProvider}
          onProviderAction={handleProviderAction}
          onTest={handleTest}
        />
      </DashboardDataCard>

      {clearanceProvider ? (
        <ProviderClearanceModal
          provider={clearanceProvider}
          onClose={() => setClearanceProvider(null)}
        />
      ) : null}

      {embeddingProvider ? (
        <EmbeddingModelModal
          provider={embeddingProvider}
          onClose={() => setEmbeddingProvider(null)}
        />
      ) : null}

      <ConnectProviderModal
        isSubmitting={isConnectingProvider}
        open={isConnectModalOpen}
        onClose={() => setIsConnectModalOpen(false)}
        onSubmit={submitConnectProvider}
      />
    </>
  );
}
