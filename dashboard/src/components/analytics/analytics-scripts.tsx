'use client';

import Script from 'next/script';

import type { AnalyticsConfig } from '@/lib/analytics/config';
import { useAnalyticsConsentStore } from '@/store/analytics-consent-store';

// Tells Google and Clarity what the visitor agreed to. The banner asks about
// analytics only, so analytics is granted and everything for advertising is not.
const CONSENT_SIGNAL = `window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('consent','default',{analytics_storage:'granted',ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'});`;

type AnalyticsScriptsProps = {
  config: AnalyticsConfig;
};

/**
 * Loads each configured provider, and only after the visitor has agreed. The
 * ids were checked on the server, so they are safe to put in a script.
 */
export function AnalyticsScripts({ config }: AnalyticsScriptsProps) {
  const consent = useAnalyticsConsentStore((state) => state.consent);

  if (consent !== 'granted') {
    return null;
  }

  const { googleAnalyticsId, googleTagManagerId, microsoftClarityId } = config;

  return (
    <>
      <Script id="analytics-consent-signal" strategy="afterInteractive">
        {CONSENT_SIGNAL}
      </Script>
      {googleTagManagerId ? (
        <Script id="google-tag-manager" strategy="afterInteractive">
          {`(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','${googleTagManagerId}');`}
        </Script>
      ) : null}
      {googleAnalyticsId ? (
        <>
          <Script
            id="google-analytics-loader"
            src={`https://www.googletagmanager.com/gtag/js?id=${googleAnalyticsId}`}
            strategy="afterInteractive"
          />
          <Script id="google-analytics" strategy="afterInteractive">
            {`window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','${googleAnalyticsId}');`}
          </Script>
        </>
      ) : null}
      {microsoftClarityId ? (
        <Script id="microsoft-clarity" strategy="afterInteractive">
          {`(function(c,l,a,r,i,t,y){c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);})(window,document,"clarity","script","${microsoftClarityId}");`}
        </Script>
      ) : null}
    </>
  );
}
