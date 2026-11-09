'use client';

import { useRouter } from 'next/navigation';
import { useCallback } from 'react';

import { getOrganizationMe } from '@/lib/api';
import { withOrgAccess } from '@/lib/auth/org-session';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

type UseApplyPasskeyLoginOptions = {
  redirectTo?: string;
};

/**
 * Shared "finish logging in" step for every org-plane passkey login path (the
 * button flow and the conditional-UI/autofill flow both funnel through this):
 * store the session exactly like a password login, best-effort backfill the
 * user's email from `/me` (passkey confirm never returns it), then redirect —
 * no MFA step, since a passkey login is already `mfa_satisfied`.
 */
export function useApplyPasskeyLogin(options?: UseApplyPasskeyLoginOptions) {
  const router = useRouter();
  const setAuth = useAuthStore((state) => state.login);
  const updateUser = useAuthStore((state) => state.updateUser);

  return useCallback(
    async (result: LoginResponse) => {
      setAuth(await withOrgAccess(result, result.user.organizationSlug ?? ''));

      try {
        if (result.user.organizationSlug) {
          const me = await getOrganizationMe(result.user.organizationSlug);
          updateUser({ email: me.email, name: me.displayName });
        }
      } catch {
        // Non-blocking — the session is already valid; email enriches lazily.
      }

      router.push(options?.redirectTo ?? '/overview');
    },
    [options?.redirectTo, router, setAuth, updateUser],
  );
}
