'use client';

import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { DashboardNavItem } from '@/types/dashboard';

/**
 * Navigation items keep their English `label` as an identifier (tabs and
 * routes are matched by it), so the visible text is looked up here. A label
 * without a message, such as a name that came from the backend, is shown as is.
 */
export function useNavLabels() {
  const t = useLooseTranslations('dashboard.nav');

  function translate(group: 'groups' | 'labels', name: string) {
    const key = `${group}.${name}`;

    return t.has(key) ? t(key) : name;
  }

  return {
    group: (name: string) => translate('groups', name),
    item: (item: Pick<DashboardNavItem, 'label'>) => translate('labels', item.label),
    label: (name: string) => translate('labels', name),
  };
}
