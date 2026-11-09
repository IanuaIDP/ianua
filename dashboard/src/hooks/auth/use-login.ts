'use client';

import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';

import { login, type TenantAuthContext } from '@/lib/api/services/auth';
import { trustCurrentDevice, trustCurrentOrgDevice } from '@/lib/api/services/devices';
import { getDeviceFingerprint } from '@/lib/auth/device';
import { withOrgAccess } from '@/lib/auth/org-session';
import { useAuthStore } from '@/store/auth-store';
import type { LoginRequest } from '@/types/auth';

type LoginVariables = {
  credentials: LoginRequest;
  trustDevice: boolean;
};

type UseLoginOptions = {
  context?: TenantAuthContext;
  redirectTo?: string;
};

export function useLogin(options?: UseLoginOptions) {
  const router = useRouter();
  const setAuth = useAuthStore((state) => state.login);
  const setTokens = useAuthStore((state) => state.setTokens);

  return useMutation({
    mutationFn: async ({ credentials }: LoginVariables) => {
      const fingerprintHash = await getDeviceFingerprint();

      return login({ ...credentials, fingerprint_hash: fingerprintHash }, options?.context);
    },
    onSuccess: async (result, variables) => {
      if (result.kind === 'choose_organization' || result.kind === 'password_change_required') {
        return;
      }

      if (result.kind !== 'authenticated') {
        setTokens({ accessToken: result.pendingResponse.accessToken });
        return;
      }

      setAuth(
        options?.context
          ? result.response
          : await withOrgAccess(result.response, result.response.user.organizationSlug ?? ''),
      );

      // Trusting needs the session this call just created, so it happens here
      // rather than alongside the password. Which plane the device is trusted
      // on follows who signed in: an admin and a workspace user keep separate
      // device lists, because they are separate accounts.
      if (variables.trustDevice) {
        await (options?.context
          ? trustCurrentDevice(options.context)
          : trustCurrentOrgDevice(result.response.user.organizationSlug ?? ''));
      }

      router.push(options?.redirectTo ?? '/overview');
    },
  });
}
