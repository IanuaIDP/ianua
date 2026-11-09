'use client';

import { useCallback } from 'react';
import { usePathname, useRouter } from 'next/navigation';

import { logout } from '@/lib/api/services/auth';
import { useAuthStore } from '@/store/auth-store';
import { getTenantRouteContext } from '@/utils/dashboard-routes';

export function useLogout() {
  const router = useRouter();
  const pathname = usePathname();
  const clearAuth = useAuthStore((state) => state.logout);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const sessionId = useAuthStore((state) => state.user?.id);
  const tenantContext = getTenantRouteContext(pathname);

  return useCallback(async () => {
    try {
      await logout({ orgSlug: organizationSlug, sessionId }, tenantContext ?? undefined);
    } finally {
      clearAuth();
      router.replace(
        tenantContext
          ? `/organizations/${encodeURIComponent(tenantContext.orgSlug)}/tenants/${encodeURIComponent(
              tenantContext.tenantSlug,
            )}/login`
          : '/login',
      );
    }
  }, [clearAuth, organizationSlug, router, sessionId, tenantContext]);
}
