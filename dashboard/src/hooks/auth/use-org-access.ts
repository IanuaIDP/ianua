'use client';

import { useCallback } from 'react';

import { getOrgAccess, hasOrgPermission } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import { getAssignableOrgRoles, getOrgRights } from '@/utils/org-role';

export function useOrgAccess() {
  const access = useAuthStore((state) => state.access);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const setAccess = useAuthStore((state) => state.setAccess);

  const role = access?.role ?? null;
  const isOwner = role === 'Owner';
  const tenants = access?.tenants ?? [];

  function hasPermission(tenantSlug: string, permission: string) {
    const tenant = tenants.find((entry) => entry.slug === tenantSlug);

    if (!tenant) {
      return false;
    }

    return hasOrgPermission(tenant.permissions, permission);
  }

  const refresh = useCallback(async () => {
    if (!organizationSlug) {
      return;
    }

    const nextAccess = await getOrgAccess(organizationSlug);
    setAccess(nextAccess);
  }, [organizationSlug, setAccess]);

  return {
    ...getOrgRights(role),
    access,
    assignableRoles: getAssignableOrgRoles(role),
    hasPermission,
    isOwner,
    refresh,
    role,
    tenants,
  };
}
