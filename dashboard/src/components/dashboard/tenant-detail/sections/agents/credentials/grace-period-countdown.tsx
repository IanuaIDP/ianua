'use client';

import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import { formatCountdown, parseBackendTimestamp } from '@/utils/date';

type GracePeriodCountdownProps = {
  graceEndsAt: string;
};

export function GracePeriodCountdown({ graceEndsAt }: GracePeriodCountdownProps) {
  const t = useTranslations('dashboard.credentials.grace');
  const target = parseBackendTimestamp(graceEndsAt);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!target) {
      return;
    }

    const intervalId = window.setInterval(() => setNow(Date.now()), 1000);

    return () => window.clearInterval(intervalId);
  }, [target]);

  if (!target) {
    return null;
  }

  const label = formatCountdown(target);
  const isExpired = target.getTime() <= now;

  return (
    <span className="inline-flex items-center gap-1">
      <span className="material-symbols-rounded text-xs!" aria-hidden>
        info
      </span>
      {isExpired
        ? t('expired')
        : t.rich('endsIn', {
            value: (chunks) => <span className="text-white">{chunks}</span>,
            time: label,
          })}
    </span>
  );
}
