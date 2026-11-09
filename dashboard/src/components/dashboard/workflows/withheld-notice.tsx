'use client';

import { useTranslations } from 'next-intl';

/** Says that data is hidden because it is above the reader's clearance. */
export function WithheldNotice() {
  const t = useTranslations('dashboard.workflows');

  return (
    <p className="flex items-center gap-2 rounded-lg bg-surfaceChip px-3 py-2 text-xs font-medium text-textGray">
      <span className="material-symbols-rounded text-sm!" aria-hidden>
        visibility_off
      </span>
      {t('withheld')}
    </p>
  );
}
