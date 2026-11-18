'use client';

import { useTranslations } from 'next-intl';

import { useAnalyticsConsentStore } from '@/store/analytics-consent-store';

type CookieSettingsButtonProps = {
  className?: string;
};

/** Reopens the consent banner. It shows only where analytics are on. */
export function CookieSettingsButton({ className }: CookieSettingsButtonProps) {
  const t = useTranslations('cookieConsent');
  const isAvailable = useAnalyticsConsentStore((state) => state.isAvailable);
  const openPanel = useAnalyticsConsentStore((state) => state.openPanel);

  if (!isAvailable) {
    return null;
  }

  return (
    <button type="button" className={className} onClick={openPanel}>
      {t('settings')}
    </button>
  );
}
