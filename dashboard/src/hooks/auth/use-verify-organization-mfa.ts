'use client';

import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';

import { verifyOrganizationMfa } from '@/lib/api/services/auth';
import { trustCurrentOrgDevice } from '@/lib/api/services/devices';
import { withOrgAccess } from '@/lib/auth/org-session';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

type VerifyOrganizationMfaPayload = {
  code: string;
};

type UseVerifyOrganizationMfaOptions = {
  orgSlug: string;
  pendingResponse: LoginResponse;
  redirectTo?: string;
  trustDevice?: boolean;
};

export function useVerifyOrganizationMfa(options: UseVerifyOrganizationMfaOptions) {
  const router = useRouter();
  const setAuth = useAuthStore((state) => state.login);

  return useMutation({
    mutationFn: async ({ code }: VerifyOrganizationMfaPayload) => {
      await verifyOrganizationMfa(options.orgSlug, code);

      return withOrgAccess(options.pendingResponse, options.orgSlug);
    },
    onSuccess: async (session) => {
      setAuth(session);

      // The box was ticked before the code was asked for, so this is the first
      // point in the flow where there is a session to trust the device against.
      if (options.trustDevice) {
        await trustCurrentOrgDevice(options.orgSlug);
      }

      router.push(options.redirectTo ?? '/overview');
    },
  });
}
