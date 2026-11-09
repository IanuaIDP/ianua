'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm, useWatch } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { PermissionScopePicker } from '@/components/dashboard/shared/permission-scope-picker';
import { DayInput } from '@/components/ui/day-input';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { getTenantPermissions } from '@/lib/api';
import {
  CreateTenantApiKeySchema,
  type CreateTenantApiKeyInput,
} from '@/schemas/tenant-api-key-schemas';
import type { Permission } from '@/types/permission';

type CreateTenantApiKeyModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: CreateTenantApiKeyInput) => void;
  open: boolean;
  orgSlug?: string;
  tenantSlug: string;
};

const createTenantApiKeyFormId = 'create-tenant-api-key-form';
const emptyFormValues: CreateTenantApiKeyInput = { endsOn: '', name: '', scopes: [] };

export function CreateTenantApiKeyModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
  tenantSlug,
}: CreateTenantApiKeyModalProps) {
  const t = useTranslations('dashboard.settings.apiKeys.createModal');
  const [isClosing, setIsClosing] = useState(false);
  const [prevOpen, setPrevOpen] = useState(open);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<CreateTenantApiKeyInput>({
    resolver: zodResolver(CreateTenantApiKeySchema),
    defaultValues: emptyFormValues,
    mode: 'onBlur',
  });
  const selectedScopes = useWatch({ control, name: 'scopes' }) ?? [];
  const endsOn = useWatch({ control, name: 'endsOn' }) ?? '';

  const {
    data: permissionGroups = [],
    error: permissionsError,
    isLoading: isLoadingPermissions,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPermissions(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-permissions', orgSlug, tenantSlug],
  });

  if (open !== prevOpen) {
    setPrevOpen(open);

    if (open) {
      setIsClosing(false);
      reset(emptyFormValues);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    setIsClosing(true);
    reset(emptyFormValues);
    onClose();
  }

  function toggleScope(permission: Permission) {
    const next = selectedScopes.includes(permission.label)
      ? selectedScopes.filter((selected) => selected !== permission.label)
      : [...selectedScopes, permission.label];

    setValue('scopes', next, { shouldDirty: true });
  }

  function toggleAllScopes(permissions: Permission[]) {
    setValue(
      'scopes',
      permissions.map((permission) => permission.label),
      { shouldDirty: true },
    );
  }

  function handleCreateApiKeySubmit(payload: CreateTenantApiKeyInput) {
    onSubmit(payload);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      autoFocus={false}
      title={t('title')}
      description={t('descriptionTenant')}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={createTenantApiKeyFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
      size="lg"
    >
      <form
        id={createTenantApiKeyFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleCreateApiKeySubmit)}
      >
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          hint={t('nameHint')}
          containerClassName="mb-0"
          {...register('name')}
          error={isClosing ? undefined : errors.name}
          disabled={isSubmitting}
        />

        <DayInput
          label={t('endsOn')}
          hint={t('endsOnHint')}
          placeholder={t('endsOnPlaceholder')}
          value={endsOn}
          onChange={(day) => setValue('endsOn', day, { shouldDirty: true, shouldValidate: true })}
          error={isClosing ? undefined : errors.endsOn}
          disabled={isSubmitting}
        />

        <PermissionScopePicker
          disabled={isSubmitting}
          error={isClosing ? undefined : errors.scopes?.message}
          groups={permissionGroups}
          hint={t('permissionsHint')}
          isLoading={isLoadingPermissions}
          isSelected={(permission) => selectedScopes.includes(permission.label)}
          loadError={permissionsError}
          onToggle={toggleScope}
          onToggleAll={toggleAllScopes}
        />
      </form>
    </Modal>
  );
}
