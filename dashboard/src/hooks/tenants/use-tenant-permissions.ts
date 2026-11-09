'use client';

import { useQuery } from '@tanstack/react-query';
import { usePathname } from 'next/navigation';

import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getCurrentTenantUser, hasAnyTenantPermission, hasTenantPermission } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import type { TenantPermissionAction, TenantPermissionResource } from '@/types/permission';
import { getManagedTenantSlug, getTenantRouteContext } from '@/utils/dashboard-routes';
import { isTenantAccessGated } from '@/utils/org-role';

function toPascalCase(value: string) {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

// Org access lists permissions as `idp:audit_log:view`; the tenant checks use
// `AuditLog:View`. A scope-less or malformed entry grants nothing.
function toTenantPermissionSet(permissions: string[]) {
  const permissionSet = new Set<string>();

  for (const permission of permissions) {
    const [, resource, action] = permission.split(':');

    if (resource && action) {
      permissionSet.add(`${toPascalCase(resource)}:${toPascalCase(action)}`);
    }
  }

  return permissionSet;
}

export function useTenantPermissions() {
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const pathname = usePathname();
  const access = useAuthStore((state) => state.access);
  const isTenantSession = access === null;
  const memberTenantSlug =
    getTenantRouteContext(pathname)?.tenantSlug ?? getManagedTenantSlug(pathname);
  const isGatedMember = isTenantAccessGated(access?.role) && Boolean(memberTenantSlug);
  const isGated = isTenantSession ? Boolean(orgSlug && tenantSlug) : isGatedMember;

  const { data: currentUser, isLoading: isLoadingTenantUser } = useQuery({
    enabled: isTenantSession && isGated,
    queryFn: () => getCurrentTenantUser(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-current-user', orgSlug, tenantSlug],
  });
  const isLoading = isTenantSession && isLoadingTenantUser;

  const memberPermissions = access?.tenants.find(
    (tenant) => tenant.slug === memberTenantSlug,
  )?.permissions;
  const permissionSet = isTenantSession
    ? (currentUser?.permissionSet ?? new Set<string>())
    : toTenantPermissionSet(memberPermissions ?? []);

  function hasPermission(resource: TenantPermissionResource, action: TenantPermissionAction) {
    if (!isGated) {
      return true;
    }

    if (isLoading) {
      return false;
    }

    return hasTenantPermission(permissionSet, resource, action);
  }

  function canView(resource: TenantPermissionResource) {
    if (!isGated) {
      return true;
    }

    if (isLoading) {
      return false;
    }

    return hasAnyTenantPermission(permissionSet, resource);
  }

  return { canView, hasPermission, isLoading: isGated && isLoading, permissionSet };
}
