'use client';

import { useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useAuthValidationMessages } from '@/hooks/auth/use-auth-validation-messages';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { getApiErrorMessage } from '@/lib/api/errors';
import {
  getTenantSignUpRules,
  signUpToTenant,
  type TenantAuthContext,
} from '@/lib/api/services/auth';
import { buildTenantSignUpSchema, type TenantSignUpInput } from '@/schemas/auth-schemas';
import type { PasswordPolicy } from '@/types/auth-config';
import { getTenantPath } from '@/utils/dashboard-routes';

type RulesState =
  { kind: 'checking' } | { kind: 'closed' } | { kind: 'open'; policy: PasswordPolicy };

type TenantSignUpFormProps = {
  context: TenantAuthContext;
};

export function TenantSignUpForm({ context }: TenantSignUpFormProps) {
  const t = useTranslations('auth.tenantSignUp');
  const [rules, setRules] = useState<RulesState>({ kind: 'checking' });
  const loginHref = `${getTenantPath(context.orgSlug, context.tenantSlug)}/login`;

  useEffect(() => {
    let isCancelled = false;

    getTenantSignUpRules(context)
      .then(({ open, passwordPolicy }) => {
        if (isCancelled) {
          return;
        }

        setRules(
          open && passwordPolicy ? { kind: 'open', policy: passwordPolicy } : { kind: 'closed' },
        );
      })
      .catch(() => {
        if (!isCancelled) {
          setRules({ kind: 'closed' });
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [context]);

  if (rules.kind === 'checking') {
    return null;
  }

  if (rules.kind === 'closed') {
    return (
      <AuthCard backToLoginHref={loginHref} title={t('closedTitle')}>
        <p className="text-center text-sm text-textGray">{t('closedBody')}</p>
      </AuthCard>
    );
  }

  return <OpenSignUpForm context={context} loginHref={loginHref} policy={rules.policy} />;
}

type OpenSignUpFormProps = {
  context: TenantAuthContext;
  loginHref: string;
  policy: PasswordPolicy;
};

function OpenSignUpForm({ context, loginHref, policy }: OpenSignUpFormProps) {
  const t = useTranslations('auth.tenantSignUp');
  const router = useRouter();
  const validationMessages = useAuthValidationMessages();
  const getRequirementsHint = usePasswordRequirementsHint();
  const requirementsHint = getRequirementsHint(policy);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const schema = useMemo(
    () => buildTenantSignUpSchema(policy, validationMessages, requirementsHint),
    [policy, requirementsHint, validationMessages],
  );
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<TenantSignUpInput>({
    resolver: zodResolver(schema),
    mode: 'onBlur',
  });

  async function onSubmit(data: TenantSignUpInput) {
    setSubmitError(null);

    try {
      await signUpToTenant(context, {
        displayName: data.displayName,
        email: data.email,
        password: data.password,
      });

      window.sessionStorage.setItem('ianua-check-email', `sign-up:${data.email}`);

      const checkEmailParams = new URLSearchParams({
        context: 'sign-up',
        email: data.email,
        org: context.orgSlug,
        tenant: context.tenantSlug,
      });

      router.push(`/sign-up/check-email?${checkEmailParams.toString()}`);
    } catch (error) {
      setSubmitError(getApiErrorMessage(error, t('failed')));
    }
  }

  return (
    <AuthCard backToLoginHref={loginHref} title={t('title')} subtitle={t('subtitle')}>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Input
          label={t('nameLabel')}
          placeholder={t('namePlaceholder')}
          {...register('displayName')}
          error={errors.displayName}
        />
        <Input
          label={t('emailLabel')}
          type="email"
          placeholder={t('emailPlaceholder')}
          {...register('email')}
          error={errors.email}
        />
        <Input
          label={t('passwordLabel')}
          type="password"
          placeholder={t('passwordPlaceholder')}
          hint={requirementsHint}
          {...register('password')}
          error={errors.password}
        />
        <Input
          label={t('confirmLabel')}
          type="password"
          placeholder={t('confirmPlaceholder')}
          {...register('confirmPassword')}
          error={errors.confirmPassword}
        />

        {submitError && (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
            {submitError}
          </p>
        )}

        <Button isLoading={isSubmitting} type="submit">
          {t('submit')}
        </Button>
      </form>
    </AuthCard>
  );
}
