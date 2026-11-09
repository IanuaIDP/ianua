'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';

import { PermissionScopePicker } from '@/components/dashboard/shared/permission-scope-picker';
import { getTenantPermissions } from '@/lib/api';
import { permissionValueKey } from '@/lib/roles/permission-format';
import type { RouteFormInput } from '@/schemas/route-schemas';
import type { Permission } from '@/types/permission';

type SystemPermissionsFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  open: boolean;
  orgSlug?: string;
  setValue: UseFormSetValue<RouteFormInput>;
  tenantSlug?: string;
};

export function SystemPermissionsField({
  control,
  errors,
  isSubmitting,
  open,
  orgSlug,
  setValue,
  tenantSlug,
}: SystemPermissionsFieldProps) {
  const t = useTranslations('dashboard.routes.fields');
  const systemPermissions = useWatch({ control, name: 'systemPermissions' }) ?? [];
  const selectedKeys = new Set(systemPermissions.map(permissionValueKey));

  const {
    data: permissionGroups = [],
    error: permissionsError,
    isLoading: isLoadingPermissions,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPermissions(orgSlug ?? '', tenantSlug ?? ''),
    queryKey: ['tenant-permissions', orgSlug, tenantSlug],
  });

  function togglePermission(permission: Permission) {
    const key = permissionValueKey(permission.value);
    const next = selectedKeys.has(key)
      ? systemPermissions.filter((value) => permissionValueKey(value) !== key)
      : [...systemPermissions, permission.value];

    setValue('systemPermissions', next, { shouldDirty: true });
  }

  function toggleAllPermissions(permissions: Permission[]) {
    setValue(
      'systemPermissions',
      permissions.map((permission) => permission.value),
      { shouldDirty: true },
    );
  }

  return (
    <PermissionScopePicker
      disabled={isSubmitting}
      error={errors.systemPermissions?.message}
      groups={permissionGroups}
      isLoading={isLoadingPermissions}
      isSelected={(permission) => selectedKeys.has(permissionValueKey(permission.value))}
      label={t('systemPermissions')}
      loadError={permissionsError}
      onToggle={togglePermission}
      onToggleAll={toggleAllPermissions}
    />
  );
}
