'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { useAnalyticsConsentStore } from '@/store/analytics-consent-store';

export function CookieConsentBanner() {
  const t = useTranslations('cookieConsent');
  const consent = useAnalyticsConsentStore((state) => state.consent);
  const isAvailable = useAnalyticsConsentStore((state) => state.isAvailable);
  const isPanelOpen = useAnalyticsConsentStore((state) => state.isPanelOpen);
  const accept = useAnalyticsConsentStore((state) => state.accept);
  const reject = useAnalyticsConsentStore((state) => state.reject);
  const closePanel = useAnalyticsConsentStore((state) => state.closePanel);

  const mustChoose = consent === 'unset';

  if (!isAvailable || consent === 'unknown' || !(mustChoose || isPanelOpen)) {
    return null;
  }

  return (
    <section
      aria-label={t('ariaLabel')}
      className="fixed inset-x-3 bottom-3 z-110 max-h-[calc(100dvh-1.5rem)] overflow-y-auto rounded-xl border border-borderGray bg-cardBg p-4 shadow-mobile-nav sm:inset-x-auto sm:bottom-6 sm:left-6 sm:w-104 sm:p-5"
    >
      <div className="flex items-start justify-between gap-3">
        <h2 className="font-['Space_Grotesk','Manrope',sans-serif] text-base font-bold text-white sm:text-lg">
          {t('title')}
        </h2>
        {mustChoose ? null : (
          <button
            type="button"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-white/70 transition-colors duration-200 hover:text-primary"
            aria-label={t('close')}
            onClick={closePanel}
          >
            <span className="material-symbols-rounded" aria-hidden="true">
              close
            </span>
          </button>
        )}
      </div>

      <p className="mt-2 text-sm leading-6 text-textGray">
        {t('description')}{' '}
        <Link href="/privacy-policy" className="text-focus hover:underline">
          {t('learnMore')}
        </Link>
      </p>

      {mustChoose ? null : (
        <p className="mt-2 text-xs text-textGray">
          {t(consent === 'granted' ? 'currentGranted' : 'currentDenied')}
        </p>
      )}

      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        <button
          type="button"
          className="inline-flex h-9 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-4 text-sm font-semibold text-white transition hover:bg-hoverBg"
          onClick={reject}
        >
          {t('reject')}
        </button>
        <button
          type="button"
          className="inline-flex h-9 items-center justify-center rounded-lg bg-focus px-4 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
          onClick={accept}
        >
          {t('accept')}
        </button>
      </div>
    </section>
  );
}
