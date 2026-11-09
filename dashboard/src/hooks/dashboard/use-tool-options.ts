import { useTranslations } from 'next-intl';

import { TOOL_ACTION_CLASSES } from '@/constants/tool';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SelectOption } from '@/types/dashboard';

/** The tool action classes as choices, worded in the current language. */
export function useToolOptions() {
  const t = useTranslations('dashboard.tools.actionClasses');
  const tLoose = useLooseTranslations('dashboard.tools.actionClasses');

  const actionClassOptions: SelectOption[] = TOOL_ACTION_CLASSES.map((id) => ({
    label: t(id),
    value: id,
  }));

  return {
    actionClassLabel: (id: string) => (tLoose.has(id) ? tLoose(id) : id),
    actionClassOptions,
  };
}
