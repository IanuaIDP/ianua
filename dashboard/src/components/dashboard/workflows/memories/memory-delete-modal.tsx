'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DeleteEntityModal } from '@/components/dashboard/shared/delete-entity-modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { deleteMemory, getApiErrorMessage } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { Memory } from '@/types/memory';

type MemoryDeleteModalProps = {
  memory: Memory | null;
  onClose: () => void;
};

/** Deleting a memory, with its name typed to confirm. It waits 30 days before it is gone. */
export function MemoryDeleteModal({ memory, onClose }: MemoryDeleteModalProps) {
  const t = useTranslations('dashboard.memories.delete');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [typedName, setTypedName] = useState('');
  const { isPending, mutate } = useMutation({
    mutationFn: (name: string) => deleteMemory(orgSlug ?? '', tenantSlug, memory?.id ?? '', name),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async () => {
      setTypedName('');
      showNotification({ message: t('done'), type: 'success' });
      onClose();
      await queryClient.invalidateQueries({ queryKey: ['memories', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  function handleClose() {
    setTypedName('');
    onClose();
  }

  return (
    <DeleteEntityModal
      confirmationValue={typedName}
      description={t('description')}
      entityName={memory?.name ?? ''}
      isSubmitting={isPending}
      open={memory !== null}
      primaryActionLabel={t('submit')}
      removeItems={[t('removeTexts'), t('removeSteps')]}
      title={t('title', { name: memory?.name ?? '' })}
      warningTitle={t('warning')}
      onClose={handleClose}
      onConfirm={() => mutate(typedName)}
      onConfirmationChange={setTypedName}
    />
  );
}
