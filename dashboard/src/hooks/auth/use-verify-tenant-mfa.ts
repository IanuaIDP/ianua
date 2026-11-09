'use client';

import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';

import { verifyTenantMfa, type TenantAuthContext } from '@/lib/api/services/auth';
import { trustCurrentDevice } from '@/lib/api/services/devices';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

type VerifyTenantMfaPayload = {
  code: string;
};

type UseVerifyTenantMfaOptions = {
  context: TenantAuthContext;
  pendingResponse: LoginResponse;
  redirectTo?: string;
  sessionId: string;
  trustDevice?: boolean;
};

export function useVerifyTenantMfa(options: UseVerifyTenantMfaOptions) {
  const router = useRouter();
  const setAuth = useAuthStore((state) => state.login);

  return useMutation({
    mutationFn: ({ code }: VerifyTenantMfaPayload) =>
      verifyTenantMfa(options.context, code, options.sessionId),
    onSuccess: async () => {
      setAuth(options.pendingResponse);

      // The box was ticked before the code was asked for, so this is the first
      // point in the flow where there is a session to trust the device against.
      if (options.trustDevice) {
        await trustCurrentDevice(options.context);
      }

      router.push(options.redirectTo ?? '/overview');
    },
  });
}
