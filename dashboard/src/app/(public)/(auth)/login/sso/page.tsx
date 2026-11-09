'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { getApiErrorMessage, startOrganizationSso } from '@/lib/api';
import { saveOrgSsoBinding } from '@/lib/auth/org-sso';

export default function OrgSsoStartPage() {
  const t = useTranslations('auth.orgSso');
  const [organization, setOrganization] = useState('');
  const { error, isPending, mutate } = useMutation({
    mutationFn: () => startOrganizationSso(organization.trim()),
    onSuccess: ({ binding, redirectUrl }) => {
      saveOrgSsoBinding(binding);
      window.location.assign(redirectUrl);
    },
  });

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard title={t('startTitle')} subtitle={t('startSubtitle')}>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            mutate();
          }}
        >
          <Input
            autoComplete="organization"
            containerClassName="mb-0"
            label={t('organizationLabel')}
            placeholder={t('organizationPlaceholder')}
            value={organization}
            onChange={(event) => setOrganization(event.target.value)}
          />
          {error ? (
            <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
              {getApiErrorMessage(error, t('startFailed'))}
            </p>
          ) : null}
          <Button type="submit" isLoading={isPending} disabled={!organization.trim()}>
            {t('continue')}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
