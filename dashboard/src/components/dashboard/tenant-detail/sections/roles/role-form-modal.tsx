'use client';

import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { PermissionScopePicker } from '@/components/dashboard/shared/permission-scope-picker';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { getTenantPermissions, getTenantResourceTypes } from '@/lib/api';
import { toCataloguePermissionGroups } from '@/lib/roles/catalogue';
import { permissionValueKey } from '@/lib/roles/permission-format';
import { CreateRoleSchema, type CreateRoleInput } from '@/schemas/role-schemas';
import type { Permission } from '@/types/permission';

type RoleFormModalProps = {
  defaultValues?: CreateRoleInput;
  description: string;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: CreateRoleInput) => void;
  open: boolean;
  orgSlug?: string;
  primaryActionLabel: string;
  tenantSlug: string;
  title: string;
};

const emptyFormValues: CreateRoleInput = { name: '', permissions: [] };
const roleFormId = 'role-form';

export function RoleFormModal({
  defaultValues,
  description,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
  primaryActionLabel,
  tenantSlug,
  title,
}: RoleFormModalProps) {
  const t = useTranslations('dashboard.tenantRoles.form');
  const [wasOpen, setWasOpen] = useState(open);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<CreateRoleInput>({
    resolver: zodResolver(CreateRoleSchema),
    defaultValues: defaultValues ?? emptyFormValues,
  });
  const selectedPermissionValues = useWatch({ control, name: 'permissions' }) ?? [];
  const selectedKeys = new Set(selectedPermissionValues.map(permissionValueKey));

  const {
    data: systemGroups = [],
    error: permissionsError,
    isLoading: isLoadingPermissions,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPermissions(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-permissions', orgSlug, tenantSlug],
  });

  // The tenant's own permissions sit in the same picker as the platform's. An
  // operator granting access should not have to know which side of that
  // boundary a permission falls on, and one that can only be typed is one that
  // can be mistyped.
  const {
    data: catalogue,
    error: catalogueError,
    isLoading: isLoadingCatalogue,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantResourceTypes(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-resource-types', orgSlug, tenantSlug],
  });

  const permissionGroups = [
    ...systemGroups,
    ...toCataloguePermissionGroups(catalogue?.items ?? []),
  ];

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      reset(defaultValues ?? emptyFormValues);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    onClose();
  }

  function findViewPermission(resource: string): Permission | undefined {
    for (const group of permissionGroups) {
      const match = group.permissions.find((candidate) => {
        const [candidateResource, candidateAction] = Object.entries(candidate.value)[0] ?? [];

        return candidateResource === resource && candidateAction === 'View';
      });

      if (match) {
        return match;
      }
    }

    return undefined;
  }

  function isViewPermissionLocked(permission: Permission): boolean {
    const [resource, action] = Object.entries(permission.value)[0] ?? [];

    if (!resource || action !== 'View') {
      return false;
    }

    return selectedPermissionValues.some((value) => {
      const [valueResource, valueAction] = Object.entries(value)[0] ?? [];

      return valueResource === resource && valueAction !== 'View' && valueAction !== 'Manage';
    });
  }

  function togglePermission(permission: Permission) {
    const key = permissionValueKey(permission.value);

    if (selectedKeys.has(key)) {
      if (isViewPermissionLocked(permission)) {
        return;
      }

      setValue(
        'permissions',
        selectedPermissionValues.filter((value) => permissionValueKey(value) !== key),
        { shouldDirty: true },
      );
      return;
    }

    const [resource, action] = Object.entries(permission.value)[0] ?? [];
    const nextValues = [...selectedPermissionValues, permission.value];

    if (resource && action !== 'View' && action !== 'Manage') {
      const viewPermission = findViewPermission(resource);
      const viewKey = viewPermission ? permissionValueKey(viewPermission.value) : undefined;
      const alreadyHasView = viewKey
        ? nextValues.some((value) => permissionValueKey(value) === viewKey)
        : true;

      if (viewPermission && !alreadyHasView) {
        nextValues.push(viewPermission.value);
      }
    }

    setValue('permissions', nextValues, { shouldDirty: true });
  }

  function toggleAllPermissions(permissions: Permission[]) {
    setValue(
      'permissions',
      permissions.map((permission) => permission.value),
      { shouldDirty: true },
    );
  }

  function handleFormSubmit(data: CreateRoleInput) {
    onSubmit(data);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      showCloseButton={false}
      primaryActionLabel={primaryActionLabel}
      primaryActionType="submit"
      primaryActionForm={roleFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
      size="lg"
    >
      <form
        id={roleFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleFormSubmit)}
      >
        <Input
          label={t('name')}
          placeholder={t('namePlaceholder')}
          containerClassName="mb-0"
          className="bg-cardBg"
          {...register('name')}
          error={errors.name}
          disabled={isSubmitting}
        />

        <PermissionScopePicker
          disabled={isSubmitting}
          error={errors.permissions?.message}
          groups={permissionGroups}
          isLocked={isViewPermissionLocked}
          isLoading={isLoadingPermissions || isLoadingCatalogue}
          isSelected={(permission) => selectedKeys.has(permissionValueKey(permission.value))}
          loadError={permissionsError ?? catalogueError}
          onToggle={togglePermission}
          onToggleAll={toggleAllPermissions}
        />
      </form>
    </Modal>
  );
}
