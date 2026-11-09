'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { createSignUpSchema, type SignUpInput } from '@/schemas/auth-schemas';
import { useAuthValidationMessages } from '@/hooks/auth/use-auth-validation-messages';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { AuthCard } from '@/components/auth/AuthCard';
import { getApiErrorMessage, signup } from '@/lib/api';

export default function SignUpPage() {
  const t = useTranslations('auth.signUp');
  const tAuth = useTranslations('auth');
  const tPolicy = useTranslations('auth.passwordPolicy');
  const validationMessages = useAuthValidationMessages();
  const strongPasswordMessage = tPolicy('strong');
  const signUpSchema = useMemo(
    () => createSignUpSchema(validationMessages, strongPasswordMessage),
    [strongPasswordMessage, validationMessages],
  );
  const router = useRouter();
  const [submitError, setSubmitError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignUpInput>({
    resolver: zodResolver(signUpSchema),
    mode: 'onBlur',
    defaultValues: { agreeToTerms: false },
  });

  async function onSubmit(data: SignUpInput) {
    setSubmitError(null);

    try {
      await signup({
        admin_email: data.adminEmail,
        admin_password: data.password,
        company_name: data.companyName,
        tenant_name: 'Production',
        admin_display_name: data.fullName,
      });

      window.sessionStorage.setItem('ianua-check-email', `sign-up:${data.adminEmail}`);
      router.push(
        `/sign-up/check-email?context=sign-up&email=${encodeURIComponent(data.adminEmail)}`,
      );
    } catch (error) {
      setSubmitError(getApiErrorMessage(error, t('failed')));
    }
  }

  return (
    <AuthLayout showSignIn showFooter>
      <AuthCard
        title={t('title')}
        subtitle={t('subtitle')}
        backToLogin={false}
        width="w-full max-w-150"
      >
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          <div className="flex flex-col gap-2">
            <span className="col-span-2 text-[10px] font-semibold text-primary uppercase">
              {t('organizationSection')}
            </span>
            <Input
              label={t('companyNameLabel')}
              placeholder={t('companyNamePlaceholder')}
              {...register('companyName')}
              error={errors.companyName}
              containerClassName="mb-0"
            />
          </div>
          <div className="flex flex-col gap-2">
            <span className="col-span-2 text-[10px] font-semibold text-primary uppercase">
              {t('accountSection')}
            </span>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Input
                label={t('fullNameLabel')}
                placeholder={t('fullNamePlaceholder')}
                {...register('fullName')}
                error={errors.fullName}
                containerClassName="mb-0"
              />

              <Input
                label={t('adminEmailLabel')}
                type="email"
                placeholder={t('adminEmailPlaceholder')}
                {...register('adminEmail')}
                error={errors.adminEmail}
                containerClassName="mb-0"
              />

              <Input
                label={t('passwordLabel')}
                type="password"
                placeholder={t('passwordPlaceholder')}
                {...register('password')}
                error={errors.password}
                hint={strongPasswordMessage}
              />
            </div>
          </div>

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
    </AuthLayout>
  );
}
