'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DATA_CLASS_LEVEL_ORDER } from '@/constants/classification';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, setTenantModelProviderClearance } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ModelProvider } from '@/types/model-provider';

type ProviderClearanceModalProps = {
  onClose: () => void;
  provider: ModelProvider;
};

/** Sets the most sensitive data runs and memories may send a provider. */
export function ProviderClearanceModal({ onClose, provider }: ProviderClearanceModalProps) {
  const t = useTranslations('dashboard.modelProviders.clearance');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [clearance, setClearance] = useState(provider.clearance ?? 'Public');
  const { isPending, mutate } = useMutation({
    mutationFn: () =>
      setTenantModelProviderClearance(orgSlug ?? '', tenantSlug, provider.id, clearance),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async () => {
      showNotification({ message: t('saved'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onClose();
    },
  });

  return (
    <Modal
      open
      description={t('description')}
      isPrimaryActionDisabled={isPending}
      isPrimaryActionLoading={isPending}
      onClose={onClose}
      onPrimaryAction={() => mutate()}
      primaryActionLabel={t('submit')}
      showCloseButton={false}
      title={t('title', { name: provider.name })}
    >
      <Select
        containerClassName="mb-0"
        label={t('level')}
        onChange={setClearance}
        options={DATA_CLASS_LEVEL_ORDER.map((level) => ({ label: level, value: level }))}
        value={clearance}
      />
    </Modal>
  );
}
