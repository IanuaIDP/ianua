import { ANALYTICS_ID_PATTERNS } from '@/constants/analytics';

export type AnalyticsConfig = {
  googleAnalyticsId: string | null;
  googleTagManagerId: string | null;
  microsoftClarityId: string | null;
};

function validId(value: string | undefined, pattern: RegExp): string | null {
  const id = value?.trim();

  return id && pattern.test(id) ? id : null;
}

/**
 * Reads the analytics ids from the environment of the running server, so an
 * installation can set or change them without a new build. A missing or
 * malformed id turns that provider off.
 */
export function analyticsConfig(): AnalyticsConfig {
  return {
    googleAnalyticsId: validId(
      process.env.GOOGLE_ANALYTICS_ID,
      ANALYTICS_ID_PATTERNS.googleAnalytics,
    ),
    googleTagManagerId: validId(
      process.env.GOOGLE_TAG_MANAGER_ID,
      ANALYTICS_ID_PATTERNS.googleTagManager,
    ),
    microsoftClarityId: validId(
      process.env.MICROSOFT_CLARITY_ID,
      ANALYTICS_ID_PATTERNS.microsoftClarity,
    ),
  };
}

export function hasAnalytics(config: AnalyticsConfig): boolean {
  return Object.values(config).some((id) => id !== null);
}
