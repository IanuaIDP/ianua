'use client';

import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useApplyTenantPasskeyLogin } from '@/hooks/auth/use-apply-tenant-passkey-login';
import {
  beginTenantPasskeyLogin,
  confirmTenantPasskeyLogin,
  getApiErrorMessage,
  toTenantLoginResult,
  type LoginResult,
  type TenantAuthContext,
} from '@/lib/api';
import {
  classifyWebAuthnError,
  encodePasskeyCredentialResponse,
  getPasskeyCredential,
} from '@/lib/auth/webauthn';

type UseTenantPasskeyLoginOptions = {
  /** Takes over a sign-in that still owes something, such as a second factor to set up. */
  onUnfinished?: (result: LoginResult) => void;
  redirectTo?: string;
};

/**
 * Tenant-plane counterpart to `usePasskeyLogin`, for the "Sign in with a passkey"
 * button on a tenant's login page. `context` is undefined when the login form
 * isn't rendering in tenant mode — `signIn` is simply never called in that case,
 * so the hook can be mounted unconditionally alongside the org-plane one.
 */
export function useTenantPasskeyLogin(
  context: TenantAuthContext | undefined,
  options?: UseTenantPasskeyLoginOptions,
) {
  const t = useTranslations('auth.passkey');
  const tCommon = useTranslations('common');
  const applyPasskeyLogin = useApplyTenantPasskeyLogin({ redirectTo: options?.redirectTo });

  const mutation = useMutation({
    mutationFn: async (email: string) => {
      if (!context) {
        throw new Error(tCommon('errors.tenantMissing'));
      }

      const ceremony = await beginTenantPasskeyLogin(context, email);

      let credential: PublicKeyCredential | null;

      try {
        credential = await getPasskeyCredential(ceremony.challenge);
      } catch (error) {
        const kind = classifyWebAuthnError(error);

        if (kind === 'cancelled' || kind === 'aborted') {
          return null;
        }

        throw new Error(kind === 'security' ? t('deviceNotSetUpSignIn') : t('signInFailedDash'));
      }

      if (!credential) {
        return null;
      }

      const response = await confirmTenantPasskeyLogin(
        context,
        ceremony.ceremonyId,
        encodePasskeyCredentialResponse(credential),
        credential.id,
      );

      return toTenantLoginResult(context, email, response);
    },
    onSuccess: async (result) => {
      if (!result) {
        return;
      }

      if (result.kind === 'authenticated') {
        await applyPasskeyLogin(result.response);
        return;
      }

      options?.onUnfinished?.(result);
    },
  });

  return {
    errorMessage: mutation.isError ? getApiErrorMessage(mutation.error, t('signInFailed')) : null,
    isPending: mutation.isPending,
    reset: mutation.reset,
    signIn: (email: string) => mutation.mutate(email),
  };
}
