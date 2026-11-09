'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { cn } from '@/utils/cn';

export function HelpCenterFeedback() {
  const t = useTranslations('helpCenter.feedback');
  const [choice, setChoice] = useState<'down' | 'up' | null>(null);

  if (choice) {
    return (
      <p className="py-2 text-center text-sm text-textGray">
        {choice === 'up' ? t('thanksYes') : t('thanksNo')}
      </p>
    );
  }

  return (
    <div className="flex flex-col items-center gap-3">
      <p className="text-sm font-semibold text-white">{t('question')}</p>
      <div className="flex items-center gap-3">
        <button
          type="button"
          aria-label={t('yes')}
          onClick={() => setChoice('up')}
          className={cn(
            'flex size-9 items-center justify-center rounded-lg border border-borderGray bg-cardBg text-lg transition hover:bg-hoverBg',
          )}
        >
          👍
        </button>
        <button
          type="button"
          aria-label={t('no')}
          onClick={() => setChoice('down')}
          className={cn(
            'flex size-9 items-center justify-center rounded-lg border border-borderGray bg-cardBg text-lg transition hover:bg-hoverBg',
          )}
        >
          👎
        </button>
      </div>
    </div>
  );
}
