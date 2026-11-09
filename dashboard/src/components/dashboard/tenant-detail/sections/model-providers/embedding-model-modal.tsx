'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, setTenantModelProviderEmbeddings } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { EmbeddingModelSchema, type EmbeddingModelFormInput } from '@/schemas/memory-schemas';
import type { ModelProvider } from '@/types/model-provider';

type EmbeddingModelModalProps = {
  onClose: () => void;
  provider: ModelProvider;
};

const formId = 'embedding-model-form';

/** Sets the embedding model a provider offers beside its chat model, for memories. */
export function EmbeddingModelModal({ onClose, provider }: EmbeddingModelModalProps) {
  const t = useTranslations('dashboard.modelProviders.embeddings');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const {
    formState: { errors },
    handleSubmit,
    register,
  } = useForm<EmbeddingModelFormInput>({
    defaultValues: { embeddingModel: provider.embeddingModel ?? '' },
    resolver: zodResolver(EmbeddingModelSchema),
  });
  const { isPending, mutate } = useMutation({
    mutationFn: (values: EmbeddingModelFormInput) =>
      setTenantModelProviderEmbeddings(
        orgSlug ?? '',
        tenantSlug,
        provider.id,
        values.embeddingModel || null,
      ),
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
      primaryActionForm={formId}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      showCloseButton={false}
      title={t('title', { name: provider.name })}
    >
      <form
        id={formId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((values) => mutate(values))}
      >
        <Input
          {...register('embeddingModel')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isPending}
          error={errors.embeddingModel}
          hint={t('hint')}
          label={t('model')}
          placeholder="text-embedding-3-small"
        />
        <p className="rounded-lg bg-orange/10 px-3 py-2 text-xs text-orange">{t('warning')}</p>
      </form>
    </Modal>
  );
}
