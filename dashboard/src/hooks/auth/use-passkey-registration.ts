'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  beginPasskeyRegistration,
  confirmPasskeyRegistration,
  getApiErrorMessage,
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

type UsePasskeyRegistrationOptions = {
  onRegistered?: () => void;
};

/**
 * Org-plane "Add passkey" ceremony, split into two steps to match the UX: the
 * browser prompt (Touch ID / Windows Hello / security key) fires as soon as the
 * user clicks "Add passkey" — before we ask them to name it — then registration
 * confirms once they've typed a name. `pendingPasskey` being non-null is the
 * signal to show the naming modal.
 */
export function usePasskeyRegistration(
  orgSlug: string | undefined,
  options?: UsePasskeyRegistrationOptions,
) {
  const t = useTranslations('auth.passkey');
  const tCommon = useTranslations('common');
  const [pendingPasskey, setPendingPasskey] = useState<PendingPasskey | null>(null);

  const beginMutation = useMutation({
    mutationFn: async () => {
      if (!orgSlug) {
        throw new Error(tCommon('errors.organizationMissing'));
      }

      const ceremony = await beginPasskeyRegistration(orgSlug);

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
      if (!orgSlug || !pendingPasskey) {
        throw new Error(tCommon('errors.organizationMissing'));
      }

      return confirmPasskeyRegistration(
        orgSlug,
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
