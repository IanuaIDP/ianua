'use client';

import { useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';
import { createForgotPasswordSchema, type ForgotPasswordInput } from '@/schemas/auth-schemas';
import { useAuthValidationMessages } from '@/hooks/auth/use-auth-validation-messages';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { AuthCard } from '@/components/auth/AuthCard';
import { getApiErrorMessage } from '@/lib/api/errors';
import {
  requestOrganizationPasswordReset,
  requestTenantPasswordReset,
  type TenantAuthContext,
} from '@/lib/api/services/auth';

type ForgotPasswordContentProps = {
  backToLoginHref?: string;
  tenantContext?: TenantAuthContext;
};

export function ForgotPasswordContent({
  backToLoginHref = '/login',
  tenantContext,
}: ForgotPasswordContentProps) {
  const t = useTranslations('auth.forgotPassword');
  const validationMessages = useAuthValidationMessages();
  const forgotPasswordSchema = useMemo(
    () => createForgotPasswordSchema(validationMessages),
    [validationMessages],
  );
  const router = useRouter();
  const [submitError, setSubmitError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordInput>({
    resolver: zodResolver(forgotPasswordSchema),
    mode: 'onBlur',
  });

  async function onSubmit(data: ForgotPasswordInput) {
    setSubmitError(null);

    try {
      if (tenantContext) {
        await requestTenantPasswordReset(tenantContext, data.email);
      } else {
        await requestOrganizationPasswordReset(data.email);
      }

      window.sessionStorage.setItem('ianua-check-email', `reset-password:${data.email}`);

      const checkEmailParams = new URLSearchParams({
        context: 'reset-password',
        email: data.email,
        ...(tenantContext ? { org: tenantContext.orgSlug, tenant: tenantContext.tenantSlug } : {}),
      });

      router.push(`/sign-up/check-email?${checkEmailParams.toString()}`);
    } catch (error) {
      setSubmitError(getApiErrorMessage(error, t('failed')));
    }
  }

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard backToLoginHref={backToLoginHref} title={t('title')} subtitle={t('subtitle')}>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          <Input
            label={t('emailLabel')}
            type="email"
            placeholder={t('emailPlaceholder')}
            {...register('email')}
            error={errors.email}
          />

          {submitError && (
            <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {submitError}
            </p>
          )}

          <Button isLoading={isSubmitting} type="submit">
            {t('confirm')}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}

export default function ForgotPasswordPage() {
  return <ForgotPasswordContent />;
}
