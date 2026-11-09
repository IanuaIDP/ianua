import { useTranslations } from 'next-intl';

import { ASSURANCE_LEVEL_IDS, MFA_POLICY_IDS, RISK_LEVEL_IDS } from '@/constants/auth-config';
import type { AuthMethod } from '@/types/auth-config';
import type { SelectOption } from '@/types/dashboard';

/** The choices of the sign-in settings screens, worded in the current language. */
export function useAuthConfigOptions() {
  const t = useTranslations('dashboard.settings.authConfig');

  const authMethodLabels: Record<AuthMethod, string> = {
    MagicLink: t('methods.MagicLink'),
    Oidc: t('methods.Oidc'),
    Passkey: t('methods.Passkey'),
    Password: t('methods.Password'),
    Saml: t('methods.Saml'),
  };
  const mfaPolicyOptions: SelectOption[] = MFA_POLICY_IDS.map((id) => ({
    label: t(`mfaPolicy.${id}`),
    value: id,
  }));
  const orgMfaPolicyOptions: SelectOption[] = MFA_POLICY_IDS.map((id) => ({
    label: t(`orgMfaPolicy.${id}`),
    value: id,
  }));
  const assuranceLevelOptions: SelectOption[] = ASSURANCE_LEVEL_IDS.map((id) => ({
    label: t(`assurance.${id}`),
    value: id,
  }));
  const riskLevelOptions: SelectOption[] = RISK_LEVEL_IDS.map((id) => ({
    label: t(`risk.${id}`),
    value: id,
  }));

  return {
    assuranceLevelOptions,
    authMethodLabels,
    mfaPolicyOptions,
    orgMfaPolicyOptions,
    riskLevelOptions,
  };
}
