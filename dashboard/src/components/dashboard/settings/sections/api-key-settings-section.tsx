'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPagination } from '@/components/dashboard/shared/dashboard-pagination';
import { ApiKeyCreatedModal } from '@/components/dashboard/settings/sections/api-keys/api-key-created-modal';
import { ApiKeysTable } from '@/components/dashboard/settings/sections/api-keys/api-keys-table';
import { CreateApiKeyModal } from '@/components/dashboard/settings/sections/api-keys/create-api-key-modal';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useTableQueryState } from '@/hooks/dashboard/use-table-query-state';
import {
  createApiKey,
  deriveErrorMessage,
  getApiErrorMessage,
  getApiKeys,
  revokeApiKey,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { CreateApiKeyInput } from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { ApiKey, ApiKeyAction, ApiKeySortField, CreatedApiKey } from '@/types/api-key';

export function ApiKeySettingsSection() {
  const t = useTranslations('dashboard.settings.apiKeys');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const {
    after,
    currentPage,
    handleNextPage,
    handlePreviousPage,
    handleRowsPerPageChange,
    handleSortChange,
    resetToFirstPage,
    rowsPerPage,
    sortDirection,
    sortField,
  } = useTableQueryState<ApiKeySortField>();
  const [createdApiKey, setCreatedApiKey] = useState<CreatedApiKey | null>(null);
  const [isCreateApiKeyModalOpen, setIsCreateApiKeyModalOpen] = useState(false);
  const {
    data: apiKeysList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug),
    queryFn: () =>
      getApiKeys(organizationSlug ?? '', {
        after,
        limit: rowsPerPage,
        sortDirection,
        sortField,
      }),
    queryKey: ['api-keys', organizationSlug, sortField, sortDirection, after, rowsPerPage],
  });
  const {
    isPending: isCreatingApiKey,
    mutate: submitCreateApiKey,
    reset: resetCreateApiKeyMutation,
  } = useMutation({
    mutationFn: (payload: CreateApiKeyInput) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return createApiKey(organizationSlug, payload);
    },
    onSuccess: async (createdApiKey) => {
      setIsCreateApiKeyModalOpen(false);
      setCreatedApiKey(createdApiKey);
      resetToFirstPage();
      showNotification({ message: t('toasts.created'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['api-keys', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('toasts.createFailed')),
        type: 'error',
      });
    },
  });

  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const handleApiKeyAction = async (apiKey: ApiKey, action: ApiKeyAction) => {
    if (!organizationSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    if (action === 'Revoke') {
      await revokeApiKey(organizationSlug, apiKey.id);
      await queryClient.invalidateQueries({ queryKey: ['api-keys', organizationSlug] });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    }
  };

  return (
    <SettingsCard
      title={t('title')}
      description={t('description')}
      className="flex max-h-[calc(100vh-5.25rem)] min-h-0 flex-col overflow-hidden"
      headerAction={
        <Button
          type="button"
          onClick={() => {
            resetCreateApiKeyMutation();
            setIsCreateApiKeyModalOpen(true);
          }}
          className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
        >
          {t('create')}
        </Button>
      }
    >
      <div className="-mx-4 -mb-4 flex min-h-0 flex-1 flex-col">
        {errorMessage ? (
          <p className="mt-4 px-4 text-sm font-medium text-error">{errorMessage}</p>
        ) : null}

        <ApiKeysTable
          apiKeys={apiKeysList?.items ?? []}
          isLoading={isLoading}
          sortDirection={sortDirection}
          sortField={sortField}
          onApiKeyAction={handleApiKeyAction}
          onSortChange={handleSortChange}
        />
        <DashboardPagination
          currentPage={currentPage}
          rowsPerPage={rowsPerPage}
          rowsPerPageSelectId="api-key-rows-per-page"
          itemCount={apiKeysList?.items.length ?? 0}
          nextCursor={apiKeysList?.nextCursor ?? null}
          onNext={handleNextPage}
          onPrevious={handlePreviousPage}
          onRowsPerPageChange={handleRowsPerPageChange}
        />
      </div>
      <CreateApiKeyModal
        isSubmitting={isCreatingApiKey}
        open={isCreateApiKeyModalOpen}
        orgSlug={organizationSlug}
        onClose={() => {
          resetCreateApiKeyMutation();
          setIsCreateApiKeyModalOpen(false);
        }}
        onSubmit={submitCreateApiKey}
      />
      <ApiKeyCreatedModal apiKey={createdApiKey} onClose={() => setCreatedApiKey(null)} />
    </SettingsCard>
  );
}
