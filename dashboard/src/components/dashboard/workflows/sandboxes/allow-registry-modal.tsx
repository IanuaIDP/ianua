'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { allowSandboxRegistry, getApiErrorMessage } from '@/lib/api';
import { AllowRegistrySchema, type AllowRegistryFormInput } from '@/schemas/sandbox-schemas';

type AllowRegistryModalProps = {
  onAllowed: () => void;
  onClose: () => void;
};

const formId = 'allow-registry-form';

/**
 * Allows an image registry. The password lives only in this form and goes
 * straight to the API, so it never reaches a query cache or a mutation's state.
 */
export function AllowRegistryModal({ onAllowed, onClose }: AllowRegistryModalProps) {
  const t = useTranslations('dashboard.sandboxes.registries.allow');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { showNotification } = useNotification();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const {
    formState: { errors },
    handleSubmit,
    register,
  } = useForm<AllowRegistryFormInput>({
    defaultValues: { host: '', password: '', username: '' },
    resolver: zodResolver(AllowRegistrySchema),
  });

  async function submit(values: AllowRegistryFormInput) {
    setIsSubmitting(true);

    try {
      await allowSandboxRegistry(orgSlug ?? '', tenantSlug, {
        host: values.host,
        password: values.password || null,
        username: values.username || null,
      });
      onAllowed();
    } catch (error) {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      open
      description={t('description')}
      isPrimaryActionDisabled={isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onClose={onClose}
      primaryActionForm={formId}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      showCloseButton={false}
      title={t('title')}
    >
      <form
        id={formId}
        autoComplete="off"
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(submit)}
      >
        <Input
          {...register('host')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isSubmitting}
          error={errors.host}
          label={t('host')}
          placeholder="registry.acme.example"
        />
        <Input
          {...register('username')}
          autoComplete="off"
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isSubmitting}
          error={errors.username}
          hint={t('loginHint')}
          label={t('username')}
        />
        <Input
          {...register('password')}
          autoComplete="new-password"
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isSubmitting}
          error={errors.password}
          label={t('password')}
          type="password"
        />
      </form>
    </Modal>
  );
}
