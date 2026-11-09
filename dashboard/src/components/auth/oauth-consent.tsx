'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { isAxiosError } from 'axios';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { BrowserFormPost } from '@/components/auth/browser-form-post';
import { spinnerIcon } from '@/components/auth/token-status-screens';
import { Button } from '@/components/ui/Button';
import { useHasTenantSession } from '@/hooks/auth/use-tenant-session';
import { getApiErrorMessage, submitOAuthConsent, type TenantAuthContext } from '@/lib/api';
import type { AuthorizeOutcome, OAuthFormPost } from '@/lib/api';
import { getSignInReturnHref } from '@/lib/auth/sign-in-return';
import { useAuthStore } from '@/store/auth-store';
import { getTenantPath } from '@/utils/dashboard-routes';

type OAuthConsentProps = {
  context: TenantAuthContext;
  request: Record<string, string>;
};

/** The request to come back with after signing in: `prompt=login` was just answered. */
function withoutLoginPrompt(request: Record<string, string>) {
  const prompts = (request.prompt ?? '')
    .split(' ')
    .filter((prompt) => prompt && prompt !== 'login');
  const remaining = new URLSearchParams(request);

  if (prompts.length > 0) {
    remaining.set('prompt', prompts.join(' '));
  } else {
    remaining.delete('prompt');
  }

  return remaining;
}

/**
 * Where an app's sign-in lands on the platform: asks the API what the request
 * needs, sends the person to sign in or asks them to agree to the scopes, and
 * hands the answer back to the app.
 */
export function OAuthConsent({ context, request }: OAuthConsentProps) {
  const t = useTranslations('auth.oauthConsent');
  const router = useRouter();
  const signOut = useAuthStore((state) => state.logout);
  const { hasSession, isHydrated } = useHasTenantSession(context.orgSlug, context.tenantSlug);
  const [scopes, setScopes] = useState<string[] | null>(null);
  const [formPost, setFormPost] = useState<OAuthFormPost | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const hasStarted = useRef(false);

  function goToSignIn() {
    const next = `${window.location.pathname}?${withoutLoginPrompt(request).toString()}`;
    const loginPath = `${getTenantPath(context.orgSlug, context.tenantSlug)}/login`;

    router.replace(`${loginPath}?next=${encodeURIComponent(next)}`);
  }

  function follow(outcome: AuthorizeOutcome) {
    if (outcome.kind === 'consent') {
      setScopes(outcome.scopes);
      return;
    }

    if (outcome.kind === 'sign_in') {
      signOut();
      goToSignIn();
      return;
    }

    if (outcome.formPost) {
      setFormPost(outcome.formPost);
      return;
    }

    if (outcome.redirectTo) {
      window.location.assign(outcome.redirectTo);
      return;
    }

    setErrorMessage(t('failed'));
  }

  function handleFailure(error: unknown) {
    if (isAxiosError(error) && error.response?.status === 401) {
      router.replace(getSignInReturnHref(context.orgSlug, context.tenantSlug));
      return;
    }

    setErrorMessage(getApiErrorMessage(error, t('failed')));
  }

  useEffect(() => {
    if (!isHydrated || hasStarted.current) {
      return;
    }

    if (!hasSession) {
      router.replace(getSignInReturnHref(context.orgSlug, context.tenantSlug));
      return;
    }

    hasStarted.current = true;
    submitOAuthConsent(context, request, 'not_asked_yet').then(follow).catch(handleFailure);
    // follow and handleFailure close over props and setters only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [context, hasSession, isHydrated, request, router]);

  async function allow() {
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      follow(await submitOAuthConsent(context, request, 'given'));
    } catch (error) {
      handleFailure(error);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      {scopes ? (
        <AuthCard title={t('title')} subtitle={t('subtitle')} backToLogin={false}>
          <ul className="flex flex-col gap-2">
            {scopes.map((scope) => (
              <li
                key={scope}
                className="rounded-lg bg-surfaceChip px-3 py-2 text-sm font-medium text-white"
              >
                {scope}
              </li>
            ))}
          </ul>
          {errorMessage ? (
            <p className="mt-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {errorMessage}
            </p>
          ) : null}
          <div className="mt-6 flex flex-col gap-2">
            <Button type="button" isLoading={isSubmitting} onClick={() => void allow()}>
              {t('allow')}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={isSubmitting}
              onClick={() =>
                router.replace(`${getTenantPath(context.orgSlug, context.tenantSlug)}/overview`)
              }
            >
              {t('decline')}
            </Button>
          </div>
        </AuthCard>
      ) : errorMessage ? (
        <AuthCard title={t('failedTitle')} subtitle={errorMessage} backToLogin={false}>
          {null}
        </AuthCard>
      ) : (
        <div className="flex flex-col items-center gap-4 text-center">
          {spinnerIcon}
          <p className="text-sm font-medium text-textGray">{t('working')}</p>
        </div>
      )}
      {formPost ? <BrowserFormPost action={formPost.action} fields={formPost.fields} /> : null}
    </AuthLayout>
  );
}
