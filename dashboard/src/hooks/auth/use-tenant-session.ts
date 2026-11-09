'use client';

import { useAuthStore } from '@/store/auth-store';

/** Whether this browser holds a tenant user's own session in this tenant. */
export function useHasTenantSession(orgSlug: string, tenantSlug: string) {
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isOrgSession = useAuthStore((state) => state.access !== null);
  const user = useAuthStore((state) => state.user);

  return {
    hasSession:
      isAuthenticated &&
      !isOrgSession &&
      user?.organizationSlug === orgSlug &&
      user?.tenantSlug === tenantSlug,
    isHydrated,
  };
}
