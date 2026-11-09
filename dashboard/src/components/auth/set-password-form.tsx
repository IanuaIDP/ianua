'use client';

import { useMemo, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { DEFAULT_AUTH_CONFIG } from '@/constants/auth-config';
import { useAuthValidationMessages } from '@/hooks/auth/use-auth-validation-messages';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { getApiErrorMessage } from '@/lib/api/errors';
import { buildAcceptInviteSchema, type AcceptInviteInput } from '@/schemas/auth-schemas';
import type { PasswordPolicy } from '@/types/auth-config';

type SetPasswordFormProps = {
  /** Further fields the step asks for, drawn above the submit button. */
  children?: ReactNode;
  onSubmit: (password: string) => Promise<void>;
  passwordPolicy?: PasswordPolicy;
  requireTermsAgreement?: boolean;
  submitErrorFallback?: string;
  submitLabel?: string;
};

export function SetPasswordForm({
  children,
  onSubmit,
  passwordPolicy = DEFAULT_AUTH_CONFIG.passwordPolicy,
  requireTermsAgreement = true,
  submitErrorFallback,
  submitLabel,
}: SetPasswordFormProps) {
  const t = useTranslations('auth.setPassword');
  const tAuth = useTranslations('auth');
  const validationMessages = useAuthValidationMessages();
  const getRequirementsHint = usePasswordRequirementsHint();
  const requirementsHint = getRequirementsHint(passwordPolicy);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const schema = useMemo(
    () => buildAcceptInviteSchema(passwordPolicy, validationMessages, requirementsHint),
    [passwordPolicy, requirementsHint, validationMessages],
  );
  const {
    control,
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting, isValid },
  } = useForm<AcceptInviteInput>({
    resolver: zodResolver(schema),
    mode: 'onChange',
  });
  const [password, confirmPassword, agreeToTerms] = useWatch({
    control,
    name: ['password', 'confirmPassword', 'agreeToTerms'],
  });
  const arePasswordsMatching = Boolean(password && confirmPassword && password === confirmPassword);
  const isSubmitDisabled =
    !isValid || !arePasswordsMatching || (requireTermsAgreement && !agreeToTerms);

  async function handleFormSubmit(data: AcceptInviteInput) {
    setSubmitError(null);

    if (requireTermsAgreement && !data.agreeToTerms) {
      setError('agreeToTerms', {
        message: validationMessages.termsRequired,
        type: 'manual',
      });
      return;
    }

    try {
      await onSubmit(data.password);
    } catch (error) {
      setSubmitError(getApiErrorMessage(error, submitErrorFallback ?? t('failed')));
    }
  }

  return (
    <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-6">
      <Input
        label={t('passwordLabel')}
        type="password"
        placeholder={t('passwordPlaceholder')}
        {...register('password')}
        error={errors.password}
        hint={requirementsHint}
      />

      <Input
        label={t('confirmLabel')}
        type="password"
        placeholder="•••••••••••••••"
        {...register('confirmPassword')}
        error={errors.confirmPassword}
      />

      {requireTermsAgreement ? (
        <Checkbox
          {...register('agreeToTerms')}
          error={errors.agreeToTerms}
          label={
            <span>
              {tAuth.rich('termsConsent', {
                privacy: (chunks) => (
                  <Link
                    href="/privacy-policy"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {chunks}
                  </Link>
                ),
                terms: (chunks) => (
                  <Link
                    href="/terms-of-use"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {chunks}
                  </Link>
                ),
              })}
            </span>
          }
        />
      ) : null}

      {children}

      {submitError && (
        <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
          {submitError}
        </p>
      )}

      <Button isLoading={isSubmitting} type="submit" disabled={isSubmitDisabled}>
        {submitLabel ?? t('submit')}
      </Button>
    </form>
  );
}
