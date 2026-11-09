'use client';

import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useApplyPasskeyLogin } from '@/hooks/auth/use-apply-passkey-login';
import {
  beginOrgPasskeyLogin,
  confirmOrgPasskeyLogin,
  getApiErrorMessage,
  toOrgLoginResult,
  type LoginResult,
} from '@/lib/api';
import {
  classifyWebAuthnError,
  encodePasskeyCredentialResponse,
  getPasskeyCredential,
} from '@/lib/auth/webauthn';

type UsePasskeyLoginOptions = {
  /** Takes over a sign-in that still owes something, such as a second factor to set up. */
  onUnfinished?: (result: LoginResult) => void;
  redirectTo?: string;
};

/**
 * Org-plane passwordless login triggered by the "Sign in with a passkey" button:
 * begin -> browser ceremony -> confirm -> hand off to `useApplyPasskeyLogin` to
 * store the session and redirect. Resolves the ceremony to `null` (not an error)
 * when the user cancels the browser prompt or we abort it ourselves — callers
 * should stay silent in that case, per the anti-enumeration UX the backend expects.
 */
export function usePasskeyLogin(options?: UsePasskeyLoginOptions) {
  const t = useTranslations('auth.passkey');
  const applyPasskeyLogin = useApplyPasskeyLogin({ redirectTo: options?.redirectTo });

  const mutation = useMutation({
    mutationFn: async (email: string) => {
      const ceremony = await beginOrgPasskeyLogin(email);

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

      const response = await confirmOrgPasskeyLogin(
        ceremony.ceremonyId,
        encodePasskeyCredentialResponse(credential),
        credential.id,
      );

      // Passkey confirm never returns the user's email — only session/org/tenant
      // ids. Store what we have now; useApplyPasskeyLogin enriches it from `/me`.
      const result = toOrgLoginResult('', response);

      if (result.kind === 'choose_organization') {
        throw new Error(t('multipleOrganizationsUsePassword'));
      }

      return result;
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
