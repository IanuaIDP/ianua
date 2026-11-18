import { AnalyticsRegistration } from '@/components/analytics/analytics-registration';
import { AnalyticsScripts } from '@/components/analytics/analytics-scripts';
import { CookieConsentBanner } from '@/components/analytics/cookie-consent-banner';
import { analyticsConfig, hasAnalytics } from '@/lib/analytics/config';

/**
 * Analytics for the pages it is placed in: the consent banner and, once the
 * visitor agrees, the configured providers. It draws nothing when no provider
 * is configured. Put it in a layout to turn analytics on for that part of the
 * app; leave it out to keep that part free of analytics.
 */
export function Analytics() {
  const config = analyticsConfig();

  if (!hasAnalytics(config)) {
    return null;
  }

  return (
    <>
      <AnalyticsRegistration />
      <AnalyticsScripts config={config} />
      <CookieConsentBanner />
    </>
  );
}
