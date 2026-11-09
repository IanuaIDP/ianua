'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { isAxiosError } from 'axios';
import { useTranslations } from 'next-intl';

import { AuthLayout } from '@/components/auth/AuthLayout';
import { BrowserFormPost } from '@/components/auth/browser-form-post';
import { TokenStatusScreen, spinnerIcon } from '@/components/auth/token-status-screens';
import { useHasTenantSession } from '@/hooks/auth/use-tenant-session';
import type { SamlFormPost, TenantAuthContext } from '@/lib/api';
import { getSignInReturnHref } from '@/lib/auth/sign-in-return';

type SamlBrowserStepProps = {
  context: TenantAuthContext;
  needsSession: boolean;
  /** Runs once, even when React mounts the page twice. */
  run: () => Promise<SamlFormPost>;
};

/**
 * The pages the platform sends a browser to for SAML: gets the signed answer,
 * then posts it on to the app or identity provider without showing anything.
 */
export function SamlBrowserStep({ context, needsSession, run }: SamlBrowserStepProps) {
  const t = useTranslations('auth.saml');
  const router = useRouter();
  const { hasSession, isHydrated } = useHasTenantSession(context.orgSlug, context.tenantSlug);
  const [answer, setAnswer] = useState<SamlFormPost | null>(null);
  const [failure, setFailure] = useState<'failed' | 'gone' | null>(null);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (!isHydrated || hasStarted.current) {
      return;
    }

    if (needsSession && !hasSession) {
      router.replace(getSignInReturnHref(context.orgSlug, context.tenantSlug));
      return;
    }

    hasStarted.current = true;
    run()
      .then(setAnswer)
      .catch((error: unknown) => {
        const status = isAxiosError(error) ? error.response?.status : undefined;

        if (status === 401 && needsSession) {
          router.replace(getSignInReturnHref(context.orgSlug, context.tenantSlug));
          return;
        }

        setFailure(status === 410 ? 'gone' : 'failed');
      });
  }, [context, hasSession, isHydrated, needsSession, router, run]);

  if (failure) {
    return (
      <TokenStatusScreen
        title={t(`${failure}.title`)}
        subtitle={t(`${failure}.subtitle`)}
        icon={<div className="text-[32px]">❌</div>}
      />
    );
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <TokenStatusScreenBody />
      {answer ? <BrowserFormPost action={answer.destination} fields={answer.fields} /> : null}
    </AuthLayout>
  );
}

function TokenStatusScreenBody() {
  const t = useTranslations('auth.saml');

  return (
    <div className="flex flex-col items-center gap-4 text-center">
      {spinnerIcon}
      <p className="text-sm font-medium text-textGray">{t('working')}</p>
    </div>
  );
}
