'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm, useWatch } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { PermissionScopePicker } from '@/components/dashboard/shared/permission-scope-picker';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { getOrgPermissions } from '@/lib/api';
import { CreateApiKeySchema, type CreateApiKeyInput } from '@/schemas/settings-schemas';
import type { Permission } from '@/types/permission';

type CreateApiKeyModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: CreateApiKeyInput) => void;
  open: boolean;
  orgSlug?: string;
};

const createApiKeyFormId = 'create-api-key-form';
const emptyFormValues: CreateApiKeyInput = { name: '', scopes: [] };

export function CreateApiKeyModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
}: CreateApiKeyModalProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const [isClosing, setIsClosing] = useState(false);
  const [prevOpen, setPrevOpen] = useState(open);
  const {
    control,
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<CreateApiKeyInput>({
    resolver: zodResolver(CreateApiKeySchema),
    defaultValues: emptyFormValues,
    mode: 'onBlur',
  });
  const selectedScopes = useWatch({ control, name: 'scopes' }) ?? [];

  const {
    data: permissionGroups = [],
    error: permissionsError,
    isLoading: isLoadingPermissions,
  } = useQuery({
    enabled: open && Boolean(orgSlug),
    queryFn: () => getOrgPermissions(orgSlug ?? ''),
    queryKey: ['org-permissions', orgSlug],
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

  function handleCreateApiKeySubmit(payload: CreateApiKeyInput) {
    onSubmit(payload);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      autoFocus={false}
      title={t('createModal.title')}
      description={t('createModal.description')}
      primaryActionLabel={t('createModal.submit')}
      primaryActionType="submit"
      primaryActionForm={createApiKeyFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
      size="lg"
    >
      <form
        id={createApiKeyFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleCreateApiKeySubmit)}
      >
        <Input
          label={t('createModal.name')}
          placeholder={t('createModal.namePlaceholder')}
          hint={t('createModal.nameHint')}
          containerClassName="mb-0"
          {...register('name')}
          error={isClosing ? undefined : errors.name}
          disabled={isSubmitting}
        />

        <PermissionScopePicker
          disabled={isSubmitting}
          error={isClosing ? undefined : errors.scopes?.message}
          groups={permissionGroups}
          hint={t('createModal.permissionsHint')}
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
