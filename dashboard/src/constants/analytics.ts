// Analytics and cookie consent settings. The text of the banner is in
// messages/<language>.json under `cookieConsent`.

export const ANALYTICS_CONSENT_STORAGE_KEY = 'ianua.analytics-consent';

export const ANALYTICS_CONSENT_VALUES = ['granted', 'denied'] as const;

// The ids are put into a script, so each one must match its provider's format
// before it is used.
export const ANALYTICS_ID_PATTERNS = {
  googleAnalytics: /^G-[A-Z0-9]{4,20}$/,
  googleTagManager: /^GTM-[A-Z0-9]{4,20}$/,
  microsoftClarity: /^[a-z0-9]{6,20}$/,
} as const;

// Cookies the three providers set. They are removed when someone withdraws
// consent.
export const ANALYTICS_COOKIE_PREFIXES = ['_ga', '_gid', '_gat', '_gcl', '_clck', '_clsk'] as const;
export const ANALYTICS_COOKIE_NAMES = ['CLID', 'ANONCHK', 'MR', 'MUID', 'SM'] as const;
