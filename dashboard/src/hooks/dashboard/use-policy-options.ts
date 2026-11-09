import { useTranslations } from 'next-intl';

import {
  ACTION_IDS,
  CONDITION_IDS,
  REQUIRED_AAL_IDS,
  RISK_THRESHOLD_IDS,
} from '@/constants/policy';
import type { SelectOption } from '@/types/dashboard';

/** The choices of the policy rule editor, worded in the current language. */
export function usePolicyOptions() {
  const t = useTranslations('dashboard.policy');

  const conditionOptions: SelectOption[] = CONDITION_IDS.map((id) => ({
    label: t(`conditions.${id}`),
    value: id,
  }));
  const actionOptions: SelectOption[] = ACTION_IDS.map((id) => ({
    label: t(`actions.${id}`),
    value: id,
  }));
  const riskThresholdOptions: SelectOption[] = RISK_THRESHOLD_IDS.map((id) => ({
    label: t(`risk.${id}`),
    value: id,
  }));
  const requiredAalOptions: SelectOption[] = REQUIRED_AAL_IDS.map((id) => ({
    label: t(`aal.${id}`),
    value: id,
  }));

  return { actionOptions, conditionOptions, requiredAalOptions, riskThresholdOptions };
}
