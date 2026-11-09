'use client';

import { useEffect, useRef, useState } from 'react';

import { getOrgAccess, switchOrganizationTenant } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';

/**
 * An organization session works in one tenant at a time. Opening another
 * tenant moves the session there first, and the tenant's screens wait for it:
 * the move retires the old session, so a request sent with it would fail.
 * Answers whether the move is still under way.
 */
export function useTenantSessionMove(tenantSlug: string | null) {
  const access = useAuthStore((state) => state.access);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const sessionTenantSlug = useAuthStore((state) => state.user?.tenantSlug);
  const setAccess = useAuthStore((state) => state.setAccess);
  const setTokens = useAuthStore((state) => state.setTokens);
  const updateUser = useAuthStore((state) => state.updateUser);
  const [failedTenantSlug, setFailedTenantSlug] = useState<string | null>(null);
  const movingTo = useRef<string | null>(null);
  const isMoving =
    access !== null &&
    Boolean(organizationSlug && tenantSlug) &&
    sessionTenantSlug !== tenantSlug &&
    failedTenantSlug !== tenantSlug;

  useEffect(() => {
    if (!isMoving || !organizationSlug || !tenantSlug || movingTo.current === tenantSlug) {
      return;
    }

    movingTo.current = tenantSlug;

    async function move(orgSlug: string, slug: string) {
      const currentAccess = await getOrgAccess(orgSlug);
      const tenant = currentAccess?.tenants.find((candidate) => candidate.slug === slug);

      setAccess(currentAccess);

      if (!tenant) {
        throw new Error('the member holds no grant on this tenant');
      }

      const { accessToken, sessionId, tenantId } = await switchOrganizationTenant(
        orgSlug,
        tenant.tenantId,
      );

      setTokens({ accessToken });
      updateUser({ id: sessionId, tenantId, tenantName: tenant.displayName, tenantSlug: slug });
    }

    move(organizationSlug, tenantSlug)
      .catch(() => setFailedTenantSlug(tenantSlug))
      .finally(() => {
        movingTo.current = null;
      });
  }, [isMoving, organizationSlug, setAccess, setTokens, tenantSlug, updateUser]);

  return isMoving;
}
