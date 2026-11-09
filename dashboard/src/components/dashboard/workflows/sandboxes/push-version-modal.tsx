'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { useRepositoryAccounts } from '@/components/dashboard/workflows/sandboxes/use-repository-accounts';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, pushSandboxVersion } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { PushVersionSchema, type PushVersionFormInput } from '@/schemas/sandbox-schemas';
import type { SandboxVersion } from '@/types/sandbox';

type PushVersionModalProps = {
  onClose: () => void;
  sandboxId: string;
  version: SandboxVersion;
};

const formId = 'push-version-form';

/** Sends a copy of a saved version to a repository's branch. */
export function PushVersionModal({ onClose, sandboxId, version }: PushVersionModalProps) {
  const t = useTranslations('dashboard.sandboxes.push');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { accounts } = useRepositoryAccounts();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
  } = useForm<PushVersionFormInput>({
    defaultValues: { accountId: '', branch: '', folder: '', repository: '' },
    resolver: zodResolver(PushVersionSchema),
  });
  const { isPending, mutate } = useMutation({
    mutationFn: (values: PushVersionFormInput) =>
      pushSandboxVersion(orgSlug ?? '', tenantSlug, sandboxId, version.id, values),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async () => {
      showNotification({ message: t('done'), type: 'success' });
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
      title={t('title', { number: version.number })}
    >
      <form
        id={formId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((values) => mutate(values))}
      >
        <Controller
          control={control}
          name="accountId"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isPending}
              error={errors.accountId}
              label={t('account')}
              onChange={field.onChange}
              options={accounts.map((account) => ({ label: account.name, value: account.id }))}
              placeholder={t('pickAccount')}
              value={field.value}
            />
          )}
        />
        <Input
          {...register('repository')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isPending}
          error={errors.repository}
          label={t('repository')}
          placeholder="acme/web"
        />
        <Input
          {...register('branch')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isPending}
          error={errors.branch}
          hint={t('branchHint')}
          label={t('branch')}
        />
        <Input
          {...register('folder')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isPending}
          error={errors.folder}
          label={t('folder')}
          placeholder="scripts/tidy"
        />
      </form>
    </Modal>
  );
}
