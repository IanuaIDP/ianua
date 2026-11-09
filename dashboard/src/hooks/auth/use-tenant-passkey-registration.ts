'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  beginTenantPasskeyRegistration,
  confirmTenantPasskeyRegistration,
  getApiErrorMessage,
  type TenantAuthContext,
} from '@/lib/api';
import {
  classifyWebAuthnError,
  createPasskeyCredential,
  encodePasskeyCredentialResponse,
} from '@/lib/auth/webauthn';
import type { ReenteredProof } from '@/types/auth';

type PendingPasskey = {
  ceremonyId: string;
  credential: PublicKeyCredential;
};

type UseTenantPasskeyRegistrationOptions = {
  onRegistered?: () => void;
};

export function useTenantPasskeyRegistration(
  context: TenantAuthContext | undefined,
  options?: UseTenantPasskeyRegistrationOptions,
) {
  const t = useTranslations('auth.passkey');
  const tCommon = useTranslations('common');
  const [pendingPasskey, setPendingPasskey] = useState<PendingPasskey | null>(null);

  const beginMutation = useMutation({
    mutationFn: async () => {
      if (!context) {
        throw new Error(tCommon('errors.tenantMissing'));
      }

      const ceremony = await beginTenantPasskeyRegistration(context);

      try {
        const credential = await createPasskeyCredential(ceremony.challenge);

        return { ceremonyId: ceremony.ceremonyId, credential };
      } catch (error) {
        const kind = classifyWebAuthnError(error);

        if (kind === 'cancelled' || kind === 'aborted') {
          return null;
        }

        throw new Error(kind === 'security' ? t('deviceNotSetUpAdd') : t('setupFailedOnDevice'));
      }
    },
    onSuccess: (result) => {
      if (result) {
        setPendingPasskey(result);
      }
    },
  });

  const confirmMutation = useMutation({
    mutationFn: ({ name, proof }: { name: string; proof: ReenteredProof }) => {
      if (!context || !pendingPasskey) {
        throw new Error(tCommon('errors.tenantMissing'));
      }

      return confirmTenantPasskeyRegistration(
        context,
        pendingPasskey.ceremonyId,
        encodePasskeyCredentialResponse(pendingPasskey.credential),
        name,
        proof,
      );
    },
    onSuccess: () => {
      setPendingPasskey(null);
      options?.onRegistered?.();
    },
  });

  return {
    beginError: beginMutation.isError
      ? getApiErrorMessage(beginMutation.error, t('setupFailed'))
      : null,
    beginRegistration: () => beginMutation.mutate(),
    confirmError: confirmMutation.isError
      ? getApiErrorMessage(confirmMutation.error, t('saveFailed'))
      : null,
    confirmRegistration: (name: string, proof: ReenteredProof) =>
      confirmMutation.mutate({ name, proof }),
    confirmErrorCause: confirmMutation.error,
    isBeginning: beginMutation.isPending,
    isConfirming: confirmMutation.isPending,
    pendingPasskey,
    reset: () => {
      setPendingPasskey(null);
      beginMutation.reset();
      confirmMutation.reset();
    },
  };
}
