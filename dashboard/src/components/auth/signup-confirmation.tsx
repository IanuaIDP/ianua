'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { Button } from '@/components/ui/Button';
import { confirmSignup, getApiErrorMessage } from '@/lib/api';

type SignupConfirmationProps = {
  token: string;
};

/** Where the mailed link lands: the organization only exists once it has been followed. */
export function SignupConfirmation({ token }: SignupConfirmationProps) {
  const t = useTranslations('auth.signUpConfirm');
  const tCommon = useTranslations('common');
  const router = useRouter();
  const [state, setState] = useState<'confirming' | 'confirmed' | 'failed'>(
    token ? 'confirming' : 'failed',
  );
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (!token || hasStarted.current) {
      return;
    }

    hasStarted.current = true;
    confirmSignup(token)
      .then(() => setState('confirmed'))
      .catch((error: unknown) => {
        setErrorMessage(getApiErrorMessage(error, t('failedSubtitle')));
        setState('failed');
      });
  }, [t, token]);

  if (state === 'confirming') {
    return (
      <AuthCard title={t('confirmingTitle')} subtitle={t('confirmingSubtitle')} backToLogin={false}>
        {null}
      </AuthCard>
    );
  }

  if (state === 'failed') {
    return (
      <AuthCard title={t('failedTitle')} subtitle={errorMessage ?? t('failedSubtitle')}>
        {null}
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title={t('doneTitle')}
      subtitle={t('doneSubtitle')}
      icon={<div className="text-[32px]">🎉</div>}
      backToLogin={false}
    >
      <Button type="button" onClick={() => router.push('/login')}>
        {tCommon('signIn')}
      </Button>
    </AuthCard>
  );
}
