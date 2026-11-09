'use client';

import { useEffect, useRef, useState } from 'react';
import { isAxiosError } from 'axios';
import { useTranslations } from 'next-intl';

import { useApplyTenantPasskeyLogin } from '@/hooks/auth/use-apply-tenant-passkey-login';
import {
  beginTenantPasskeyDiscovery,
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
  isPasskeyConditionalMediationAvailable,
  isPasskeySupported,
} from '@/lib/auth/webauthn';

type UseTenantPasskeyAutofillOptions = {
  context?: TenantAuthContext;
  enabled?: boolean;
  /** Takes over a sign-in that still owes something; must keep its identity between renders. */
  onUnfinished?: (result: LoginResult) => void;
  redirectTo?: string;
};

/**
 * Tenant-plane counterpart to `usePasskeyAutofill`. Depends on the context's
 * primitive fields rather than the object itself, since callers typically build
 * a fresh `{ orgSlug, tenantSlug }` object on every render — depending on the
 * object would restart the discovery loop on every render instead of only when
 * the tenant actually changes.
 */
export function useTenantPasskeyAutofill(options?: UseTenantPasskeyAutofillOptions) {
  const t = useTranslations('auth.passkey');
  const contextOrgSlug = options?.context?.orgSlug;
  const contextTenantSlug = options?.context?.tenantSlug;
  const enabled = (options?.enabled ?? true) && Boolean(contextOrgSlug && contextTenantSlug);
  const applyPasskeyLogin = useApplyTenantPasskeyLogin({ redirectTo: options?.redirectTo });
  const onUnfinished = options?.onUnfinished;
  const abortControllerRef = useRef<AbortController | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled || !contextOrgSlug || !contextTenantSlug) {
      return;
    }

    const context: TenantAuthContext = { orgSlug: contextOrgSlug, tenantSlug: contextTenantSlug };
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
          const ceremony = await beginTenantPasskeyDiscovery(context);
          const credential = await getPasskeyCredential(ceremony.challenge, {
            mediation: 'conditional',
            signal: controller.signal,
          });

          if (isCancelled || !credential) {
            return;
          }

          const response = await confirmTenantPasskeyLogin(
            context,
            ceremony.ceremonyId,
            encodePasskeyCredentialResponse(credential),
            credential.id,
          );

          const result = toTenantLoginResult(context, '', response);

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
  }, [applyPasskeyLogin, contextOrgSlug, contextTenantSlug, enabled, onUnfinished, t]);

  return {
    abort: () => abortControllerRef.current?.abort(),
    errorMessage,
  };
}
