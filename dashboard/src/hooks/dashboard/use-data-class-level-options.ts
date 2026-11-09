import { useTranslations } from 'next-intl';

import { DATA_CLASS_LEVEL_ORDER } from '@/constants/classification';
import type { SelectOption } from '@/types/dashboard';

/** The data sensitivity levels as choices, worded in the current language. */
export function useDataClassLevelOptions(): SelectOption[] {
  const t = useTranslations('dashboard.status');

  return DATA_CLASS_LEVEL_ORDER.map((level) => ({ label: t(level), value: level }));
}
