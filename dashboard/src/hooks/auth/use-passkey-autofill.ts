'use client';

import { useEffect, useRef, useState } from 'react';
import { isAxiosError } from 'axios';
import { useTranslations } from 'next-intl';

import { useApplyPasskeyLogin } from '@/hooks/auth/use-apply-passkey-login';
import {
  beginOrgPasskeyDiscovery,
  confirmOrgPasskeyLogin,
  getApiErrorMessage,
  toOrgLoginResult,
  type LoginResult,
} from '@/lib/api';
import {
  classifyWebAuthnError,
  encodePasskeyCredentialResponse,
  getPasskeyCredential,
  isPasskeyConditionalMediationAvailable,
  isPasskeySupported,
} from '@/lib/auth/webauthn';

type UsePasskeyAutofillOptions = {
  enabled?: boolean;
  /** Takes over a sign-in that still owes something; must keep its identity between renders. */
  onUnfinished?: (result: LoginResult) => void;
  redirectTo?: string;
};

/**
 * Org-plane conditional UI (autofill): offers a saved passkey straight from the
 * email field's autocomplete dropdown, before the user types anything. The email
 * input needs `autocomplete="username webauthn"` for the browser to attach the
 * dropdown. Runs silently in the background while idle — no loading/error UI —
 * since the button flow (`usePasskeyLogin`) is always there as a visible
 * fallback. Once the user actually picks a credential from the dropdown,
 * though, they've engaged with it directly, so a real failure (e.g. the
 * passkey was removed server-side) is surfaced via `errorMessage`.
 *
 * Call the returned `abort()` when the user submits the password form instead,
 * so the pending `navigator.credentials.get()` doesn't linger.
 */
export function usePasskeyAutofill(options?: UsePasskeyAutofillOptions) {
  const t = useTranslations('auth.passkey');
  const enabled = options?.enabled ?? true;
  const applyPasskeyLogin = useApplyPasskeyLogin({ redirectTo: options?.redirectTo });
  const onUnfinished = options?.onUnfinished;
  const abortControllerRef = useRef<AbortController | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let isCancelled = false;

    async function runAutofillLoop() {
      const [supported, conditionalAvailable] = await Promise.all([
        isPasskeySupported(),
        isPasskeyConditionalMediationAvailable(),
      ]);

      if (!supported || !conditionalAvailable || isCancelled) {
        return;
      }

      while (!isCancelled) {
        const controller = new AbortController();
        abortControllerRef.current = controller;

        try {
          const ceremony = await beginOrgPasskeyDiscovery();
          const credential = await getPasskeyCredential(ceremony.challenge, {
            mediation: 'conditional',
            signal: controller.signal,
          });

          if (isCancelled || !credential) {
            return;
          }

          const response = await confirmOrgPasskeyLogin(
            ceremony.ceremonyId,
            encodePasskeyCredentialResponse(credential),
            credential.id,
          );

          const result = toOrgLoginResult('', response);

          if (result.kind === 'choose_organization') {
            setErrorMessage(t('multipleOrganizationsUsePassword'));
            return;
          }

          if (result.kind === 'authenticated') {
            await applyPasskeyLogin(result.response);
            return;
          }

          onUnfinished?.(result);
          return;
        } catch (error) {
          const kind = classifyWebAuthnError(error);

          if (kind === 'aborted' || kind === 'cancelled') {
            return;
          }

          if (isAxiosError(error) && error.response?.status === 422) {
            continue;
          }

          setErrorMessage(getApiErrorMessage(error, t('signInFailed')));
          return;
        }
      }
    }

    void runAutofillLoop();

    return () => {
      isCancelled = true;
      abortControllerRef.current?.abort();
    };
  }, [applyPasskeyLogin, enabled, onUnfinished, t]);

  return {
    abort: () => abortControllerRef.current?.abort(),
    errorMessage,
  };
}
