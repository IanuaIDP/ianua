import { useTranslations } from 'next-intl';

import {
  ATTESTATION_METHODS,
  ATTESTATION_REATTEST_INTERVAL_SECONDS,
  CREDENTIAL_EXPIRY_SECONDS,
} from '@/constants/credential';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { Credential, CredentialAction } from '@/types/credential';
import type { DashboardActionModalContent, SelectOption } from '@/types/dashboard';

/** Credential choices and dialogs, worded in the current language. */
export function useCredentialText() {
  const t = useTranslations('dashboard.credentials');
  const tIntervals = useLooseTranslations('dashboard.credentials.reattestIntervals');
  const tExpiry = useLooseTranslations('dashboard.credentials.expiry');

  const reattestIntervalOptions: SelectOption[] = ATTESTATION_REATTEST_INTERVAL_SECONDS.map(
    (seconds) => ({ label: tIntervals(seconds), value: seconds }),
  );
  const expiryOptions: SelectOption[] = CREDENTIAL_EXPIRY_SECONDS.map((seconds) => ({
    label: tExpiry(seconds || 'default'),
    value: seconds,
  }));
  const attestationMethodOptions = ATTESTATION_METHODS.map((method) => ({
    label: t(`methods.${method}`),
    value: method,
  }));

  function actionModalContent(
    credential: Credential,
  ): Partial<Record<CredentialAction, DashboardActionModalContent>> {
    return {
      Revoke: {
        title: t('revokeModal.title', { kid: credential.kid }),
        description: t('revokeModal.description'),
        primaryActionLabel: t('revokeModal.submit'),
        warningTone: 'danger',
      },
    };
  }

  return { actionModalContent, attestationMethodOptions, expiryOptions, reattestIntervalOptions };
}
