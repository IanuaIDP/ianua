'use client';

import { useRouter } from 'next/navigation';
import { useCallback } from 'react';

import { getCurrentTenantUser } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

type UseApplyTenantPasskeyLoginOptions = {
  redirectTo?: string;
};

export function useApplyTenantPasskeyLogin(options?: UseApplyTenantPasskeyLoginOptions) {
  const router = useRouter();
  const setAuth = useAuthStore((state) => state.login);
  const updateUser = useAuthStore((state) => state.updateUser);

  return useCallback(
    async (result: LoginResponse) => {
      setAuth(result);

      try {
        const { organizationSlug, tenantSlug } = result.user;

        if (organizationSlug && tenantSlug) {
          const me = await getCurrentTenantUser(organizationSlug, tenantSlug);
          updateUser({ email: me.email, name: me.name });
        }
      } catch {
        // Non-blocking — the session is already valid; name/email enrich lazily.
      }

      router.push(options?.redirectTo ?? '/overview');
    },
    [options?.redirectTo, router, setAuth, updateUser],
  );
}
