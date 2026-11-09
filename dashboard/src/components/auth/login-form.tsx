'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type KeyboardEvent,
  type MouseEvent,
} from 'react';
import { useTranslations } from 'next-intl';
import { useForm } from 'react-hook-form';
import { useMutation } from '@tanstack/react-query';
import { zodResolver } from '@hookform/resolvers/zod';

import { AuthCard } from '@/components/auth/AuthCard';
import { DuePasswordChangeStep } from '@/components/auth/due-password-change-step';
import { MfaEnrollmentStep } from '@/components/auth/mfa-enrollment-step';
import { MfaVerificationStep } from '@/components/auth/mfa-verification-step';
import { SocialButton } from '@/components/auth/SocialButton';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Link } from '@/components/ui/Link';
import { getTenantPath } from '@/utils/dashboard-routes';
import { getInitials } from '@/utils/initials';
import { useAuthValidationMessages } from '@/hooks/auth/use-auth-validation-messages';
import { useLogin } from '@/hooks/auth/use-login';
import { usePasskeyAutofill } from '@/hooks/auth/use-passkey-autofill';
import { usePasskeyLogin } from '@/hooks/auth/use-passkey-login';
import { usePasskeySupport } from '@/hooks/auth/use-passkey-support';
import { useTenantPasskeyAutofill } from '@/hooks/auth/use-tenant-passkey-autofill';
import { useTenantPasskeyLogin } from '@/hooks/auth/use-tenant-passkey-login';
import { useTenantSignInOptions } from '@/hooks/auth/use-tenant-sign-in-options';
import { useTenantSignUpOpen } from '@/hooks/auth/use-tenant-sign-up-open';
import { getApiErrorMessage } from '@/lib/api/errors';
import {
  requestTenantMagicLink,
  type LoginResult,
  type OfferedOrganization,
} from '@/lib/api/services/auth';
import { withSsoState } from '@/lib/auth/sso-state';
import { clearWaitingSignIn, saveWaitingSignIn } from '@/lib/auth/waiting-sign-in';
import { createLoginSchema, type LoginInput } from '@/schemas/auth-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

type LoginFormProps = {
  forgotPasswordHref?: string;
  orgSlug?: string;
  ssoFailed?: boolean;
  /** Where to go after signing in, when a page sent the person here. */
  nextPath?: string;
  /** How a sign-out at the app or identity provider went. */
  logoutStatus?: string;
  tenantSlug?: string;
};

type MfaContext = {
  mustEnrol: boolean;
  orgSlug: string;
  pendingResponse: LoginResponse;
  sessionId: string;
  tenantSlug?: string;
  trustDevice: boolean;
};

type LoginStep = 'email' | 'password';

type PasswordChange = Extract<LoginResult, { kind: 'password_change_required' }>;

export function LoginForm({
  forgotPasswordHref = '/forgot-password',
  orgSlug,
  ssoFailed = false,
  nextPath,
  logoutStatus,
  tenantSlug,
}: LoginFormProps) {
  const t = useTranslations('auth.login');
  const tCommon = useTranslations('common');
  const tConfirmation = useTranslations('auth.signInConfirmation');
  const validationMessages = useAuthValidationMessages();
  const loginSchema = useMemo(() => createLoginSchema(validationMessages), [validationMessages]);
  const [step, setStep] = useState<LoginStep>('email');
  const [mfaContext, setMfaContext] = useState<MfaContext | null>(null);
  const [isWaitingForEmail, setIsWaitingForEmail] = useState(false);
  const [shouldTrustDevice, setShouldTrustDevice] = useState(false);
  const [offeredOrganizations, setOfferedOrganizations] = useState<OfferedOrganization[] | null>(
    null,
  );
  const [passwordChange, setPasswordChange] = useState<PasswordChange | null>(null);
  const logout = useAuthStore((state) => state.logout);
  const setTokens = useAuthStore((state) => state.setTokens);
  const continueSignIn = useCallback((result: LoginResult, trustDevice: boolean) => {
    if (result.kind === 'authenticated') {
      return;
    }

    if (result.kind === 'choose_organization') {
      setOfferedOrganizations(result.organizations);
      return;
    }

    if (result.kind === 'password_change_required') {
      setPasswordChange(result);
      return;
    }

    if (result.kind === 'email_confirmation_required') {
      saveWaitingSignIn(result);
      setIsWaitingForEmail(true);
      return;
    }

    setMfaContext({
      mustEnrol:
        result.kind === 'mfa_enrollment_required' ||
        result.kind === 'tenant_mfa_enrollment_required',
      orgSlug: result.orgSlug,
      pendingResponse: result.pendingResponse,
      sessionId: result.sessionId,
      tenantSlug: 'tenantSlug' in result ? result.tenantSlug : undefined,
      trustDevice,
    });
  }, []);
  const continuePasskeySignIn = useCallback(
    (result: LoginResult) => {
      if ('pendingResponse' in result) {
        setTokens({ accessToken: result.pendingResponse.accessToken });
      }

      continueSignIn(result, false);
    },
    [continueSignIn, setTokens],
  );
  const tenantLoginContext =
    orgSlug && tenantSlug
      ? {
          orgSlug,
          tenantSlug,
        }
      : undefined;
  const tenantPath = tenantLoginContext
    ? getTenantPath(tenantLoginContext.orgSlug, tenantLoginContext.tenantSlug)
    : undefined;
  const redirectTo = nextPath ?? (tenantPath ? `${tenantPath}/overview` : undefined);
  const loginMutation = useLogin({
    context: tenantLoginContext,
    redirectTo,
  });
  const orgPasskeyLogin = usePasskeyLogin({ onUnfinished: continuePasskeySignIn, redirectTo });
  const tenantPasskeyLogin = useTenantPasskeyLogin(tenantLoginContext, {
    onUnfinished: continuePasskeySignIn,
    redirectTo,
  });
  const passkeyLogin = tenantLoginContext ? tenantPasskeyLogin : orgPasskeyLogin;
  const canUsePasskeyLogin = usePasskeySupport();
  const passkeyAutofill = usePasskeyAutofill({
    enabled: !tenantLoginContext,
    onUnfinished: continuePasskeySignIn,
    redirectTo,
  });
  const tenantPasskeyAutofill = useTenantPasskeyAutofill({
    context: tenantLoginContext,
    enabled: Boolean(tenantLoginContext),
    onUnfinished: continuePasskeySignIn,
    redirectTo,
  });
  const canSignUp = useTenantSignUpOpen(orgSlug, tenantSlug);
  const signInOptions = useTenantSignInOptions(orgSlug, tenantSlug);
  const offersPasskey = canUsePasskeyLogin && (!tenantLoginContext || signInOptions.passkey);
  const magicLink = useMutation({
    mutationFn: (email: string) => {
      if (!tenantLoginContext) {
        throw new Error(t('linksOnlyForWorkspace'));
      }

      return requestTenantMagicLink(tenantLoginContext, email);
    },
  });
  const {
    register,
    handleSubmit,
    getValues,
    setFocus,
    trigger,
    formState: { errors },
  } = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
    mode: 'onBlur',
  });

  useEffect(() => {
    setFocus(step === 'email' ? 'email' : 'password');
  }, [step, setFocus]);

  async function goToPasswordStep() {
    const isEmailValid = await trigger('email');

    if (!isEmailValid) {
      setFocus('email');
      return;
    }

    setStep('password');
  }

  function handleEmailKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== 'Enter') {
      return;
    }

    event.preventDefault();
    void goToPasswordStep();
  }

  async function handlePasskeyClick() {
    const isEmailValid = await trigger('email');

    if (!isEmailValid) {
      setFocus('email');
      return;
    }

    passkeyAutofill.abort();
    tenantPasskeyAutofill.abort();
    passkeyLogin.signIn(getValues('email'));
  }

  async function handleMagicLinkClick() {
    const isEmailValid = await trigger('email');

    if (!isEmailValid) {
      setFocus('email');
      return;
    }

    magicLink.mutate(getValues('email'));
  }

  async function signIn(credentials: LoginInput & { organization?: string }) {
    try {
      const result = await loginMutation.mutateAsync({
        credentials,
        trustDevice: shouldTrustDevice,
      });

      continueSignIn(result, shouldTrustDevice);
    } catch {
      // Surfaced via loginMutation.isError below.
    }
  }

  async function onSubmit(data: LoginInput) {
    passkeyAutofill.abort();
    tenantPasskeyAutofill.abort();

    await signIn(data);
  }

  function startSingleSignOn(event: MouseEvent<HTMLAnchorElement>, startHref: string) {
    event.preventDefault();
    window.location.assign(withSsoState(startHref));
  }

  if (isWaitingForEmail) {
    return (
      <AuthCard
        title={tConfirmation('checkEmailTitle')}
        subtitle={tConfirmation('checkEmailSubtitle')}
        onBackToLogin={() => {
          clearWaitingSignIn();
          logout();
          setIsWaitingForEmail(false);
        }}
      >
        {null}
      </AuthCard>
    );
  }

  if (offeredOrganizations) {
    return (
      <AuthCard
        title={t('chooseOrganizationTitle')}
        subtitle={t('chooseOrganizationSubtitle')}
        onBackToLogin={() => setOfferedOrganizations(null)}
      >
        <div className="space-y-2">
          {offeredOrganizations.map((organization) => (
            <button
              key={organization.slug}
              type="button"
              disabled={loginMutation.isPending}
              onClick={() => void signIn({ ...getValues(), organization: organization.slug })}
              className="flex w-full items-center gap-3 rounded-lg border border-borderGray px-3 py-2 text-left transition hover:bg-hoverBg disabled:pointer-events-none disabled:opacity-50"
            >
              <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
                {getInitials(organization.name) || '?'}
              </span>
              <span className="min-w-0 flex-1 truncate text-sm font-medium text-white">
                {organization.name}
              </span>
            </button>
          ))}

          {loginMutation.isError ? (
            <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {getApiErrorMessage(loginMutation.error, t('invalidCredentials'))}
            </p>
          ) : null}
        </div>
      </AuthCard>
    );
  }

  if (passwordChange && tenantLoginContext) {
    return (
      <DuePasswordChangeStep
        changeToken={passwordChange.changeToken}
        context={tenantLoginContext}
        email={getValues('email')}
        proof={passwordChange.proof}
        onBack={() => setPasswordChange(null)}
        onContinue={(result) => {
          setPasswordChange(null);
          continuePasskeySignIn(result);
        }}
      />
    );
  }

  if (mfaContext?.mustEnrol) {
    return (
      <MfaEnrollmentStep
        orgSlug={mfaContext.orgSlug}
        tenantSlug={mfaContext.tenantSlug}
        pendingResponse={mfaContext.pendingResponse}
        redirectTo={redirectTo}
        sessionId={mfaContext.sessionId}
        trustDevice={mfaContext.trustDevice}
        onBack={() => {
          logout();
          setMfaContext(null);
        }}
      />
    );
  }

  if (mfaContext) {
    return (
      <MfaVerificationStep
        orgSlug={mfaContext.orgSlug}
        pendingResponse={mfaContext.pendingResponse}
        redirectTo={redirectTo}
        sessionId={mfaContext.sessionId}
        tenantSlug={mfaContext.tenantSlug}
        trustDevice={mfaContext.trustDevice}
        onBack={() => {
          logout();
          setMfaContext(null);
        }}
      />
    );
  }

  const email = getValues('email');

  return (
    <AuthCard
      title={t('title')}
      subtitle={step === 'email' ? t('emailStepSubtitle') : t('passwordStepSubtitle')}
      backToLogin={false}
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Input
          label={t('emailLabel')}
          type="email"
          placeholder={t('emailPlaceholder')}
          autoComplete={canUsePasskeyLogin ? 'username webauthn' : 'email'}
          containerClassName={step === 'email' ? undefined : 'hidden'}
          {...register('email')}
          onKeyDown={handleEmailKeyDown}
          error={errors.email}
        />

        {step === 'password' ? (
          <button
            type="button"
            onClick={() => setStep('email')}
            className="-mt-2 flex w-full items-center gap-3 rounded-lg border border-borderGray px-3 py-2 text-left transition hover:bg-hoverBg"
          >
            <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
              {getInitials(email) || '?'}
            </span>
            <span className="min-w-0 flex-1 truncate text-sm font-medium text-white">{email}</span>
            <span className="material-symbols-rounded shrink-0 text-textGray" aria-hidden="true">
              edit
            </span>
          </button>
        ) : null}

        {step === 'email' ? (
          <Button type="button" onClick={goToPasswordStep}>
            {t('next')}
          </Button>
        ) : null}

        <div className={step === 'password' ? undefined : 'hidden'}>
          <Input
            label={t('passwordLabel')}
            type="password"
            placeholder={t('passwordPlaceholder')}
            {...register('password')}
            error={errors.password}
          />
          <div className="flex items-center justify-between gap-3">
            <Checkbox
              checked={shouldTrustDevice}
              label={t('trustDevice')}
              name="trustDevice"
              onChange={(event) => setShouldTrustDevice(event.target.checked)}
            />
            <Link href={forgotPasswordHref} className="font-medium">
              {t('forgotPassword')}
            </Link>
          </div>
        </div>

        {step === 'password' && loginMutation.isError && (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
            {getApiErrorMessage(loginMutation.error, t('invalidCredentials'))}
          </p>
        )}

        {step === 'password' ? (
          <Button
            isLoading={loginMutation.isPending}
            disabled={loginMutation.isPending}
            type="submit"
          >
            {tCommon('signIn')}
          </Button>
        ) : null}

        {ssoFailed ? (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
            {t('ssoFailed')}
          </p>
        ) : null}

        {logoutStatus === 'success' ? (
          <p className="rounded-lg border border-borderGray bg-surfaceChip px-3 py-2 text-sm text-textGray">
            {t('logoutSucceeded')}
          </p>
        ) : null}

        {logoutStatus === 'partial' || logoutStatus === 'failed' ? (
          <p className="rounded-lg border border-orange/50 bg-orange/10 px-3 py-2 text-sm text-orange">
            {t('logoutIncomplete')}
          </p>
        ) : null}

        {step === 'email' && !tenantLoginContext ? (
          <Link href="/login/sso" className="text-center text-xs font-medium text-primary">
            {t('useSso')}
          </Link>
        ) : null}

        {step === 'email' && tenantLoginContext && nextPath ? (
          <Link
            href={`/login?next=${encodeURIComponent(nextPath)}`}
            className="text-center text-xs font-medium text-primary"
          >
            {t('useCompanyAccount')}
          </Link>
        ) : null}

        {step === 'email' &&
        (offersPasskey || signInOptions.magicLink || signInOptions.connections.length > 0) ? (
          <>
            <div className="relative -mx-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-borderGray"></div>
              </div>
              <div className="relative flex justify-center text-xs">
                <span className="px-2 bg-cardBg text-textGray tracking-widest font-semibold">
                  {t('or')}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2.5">
              {signInOptions.connections.map((option) => (
                <a
                  key={option.id}
                  href={option.href}
                  onClick={(event) => startSingleSignOn(event, option.href)}
                  className="w-full h-10.5 flex items-center justify-center gap-2.5 px-4 border border-borderGray rounded-lg text-sm font-semibold hover:bg-hoverBg transition duration-200"
                >
                  <span className="material-symbols-rounded text-textGray" aria-hidden="true">
                    domain
                  </span>
                  {t('signInWith', { name: option.name })}
                </a>
              ))}
              {signInOptions.magicLink ? (
                <button
                  type="button"
                  onClick={() => void handleMagicLinkClick()}
                  disabled={magicLink.isPending || magicLink.isSuccess}
                  className="w-full h-10.5 flex items-center justify-center gap-2.5 px-4 border border-borderGray rounded-lg text-sm font-semibold hover:bg-hoverBg transition duration-200 disabled:pointer-events-none disabled:opacity-50"
                >
                  <span className="material-symbols-rounded text-textGray" aria-hidden="true">
                    mail
                  </span>
                  {magicLink.isPending ? t('sending') : t('emailMeLink')}
                </button>
              ) : null}
              {offersPasskey ? (
                <SocialButton
                  provider="passkey"
                  isLoading={passkeyLogin.isPending}
                  disabled={loginMutation.isPending}
                  onClick={handlePasskeyClick}
                />
              ) : null}
            </div>

            {magicLink.isSuccess ? (
              <p className="rounded-lg bg-primary/15 px-3 py-2 text-sm text-white">
                {t('linkSent')}
              </p>
            ) : null}

            {magicLink.isError ? (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
                {getApiErrorMessage(magicLink.error, t('linkFailed'))}
              </p>
            ) : null}

            {(passkeyLogin.errorMessage ||
              passkeyAutofill.errorMessage ||
              tenantPasskeyAutofill.errorMessage) && (
              <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
                {passkeyLogin.errorMessage ||
                  passkeyAutofill.errorMessage ||
                  tenantPasskeyAutofill.errorMessage}
              </p>
            )}
          </>
        ) : null}

        {canSignUp && tenantPath ? (
          <p className="text-center text-sm text-textGray">
            {t.rich('newHere', {
              link: (chunks) => (
                <Link href={`${tenantPath}/sign-up`} className="font-medium">
                  {chunks}
                </Link>
              ),
            })}
          </p>
        ) : null}
      </form>
    </AuthCard>
  );
}
