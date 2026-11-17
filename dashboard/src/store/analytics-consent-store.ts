import { create } from 'zustand';

import { ANALYTICS_CONSENT_STORAGE_KEY } from '@/constants/analytics';
import { clearAnalyticsCookies } from '@/lib/analytics/cookies';

export type AnalyticsConsent = 'unknown' | 'unset' | 'granted' | 'denied';

type AnalyticsConsentState = {
  consent: AnalyticsConsent;
  isAvailable: boolean;
  isPanelOpen: boolean;
};

type AnalyticsConsentActions = {
  accept: () => void;
  closePanel: () => void;
  openPanel: () => void;
  register: () => void;
  reject: () => void;
};

function readStoredConsent(): AnalyticsConsent {
  try {
    const stored = window.localStorage.getItem(ANALYTICS_CONSENT_STORAGE_KEY);

    return stored === 'granted' || stored === 'denied' ? stored : 'unset';
  } catch {
    return 'unset';
  }
}

function storeConsent(consent: 'granted' | 'denied') {
  try {
    window.localStorage.setItem(ANALYTICS_CONSENT_STORAGE_KEY, consent);
  } catch {
    // The choice then lasts only until the page is closed.
  }
}

/**
 * The visitor's analytics choice. It is `unknown` until the browser has been
 * read, so the banner does not flash for someone who already chose.
 */
export const useAnalyticsConsentStore = create<AnalyticsConsentState & AnalyticsConsentActions>(
  (set, get) => ({
    consent: 'unknown',
    isAvailable: false,
    isPanelOpen: false,
    accept: () => {
      storeConsent('granted');
      set({ consent: 'granted', isPanelOpen: false });
    },
    closePanel: () => set({ isPanelOpen: false }),
    openPanel: () => set({ isPanelOpen: true }),
    register: () => set({ consent: readStoredConsent(), isAvailable: true }),
    reject: () => {
      const wasGranted = get().consent === 'granted';

      storeConsent('denied');
      set({ consent: 'denied', isPanelOpen: false });

      if (wasGranted) {
        clearAnalyticsCookies();
        window.location.reload();
      }
    },
  }),
);
