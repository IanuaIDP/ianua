'use client';

import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Button } from '@/components/ui/Button';
import { formatCountdown } from '@/utils/countdown';

export const spinnerIcon = (
  <span className="material-symbols-rounded animate-spin text-[32px] text-primary">
    progress_activity
  </span>
);

type TokenStatusScreenProps = {
  title: string;
  subtitle: string;
  icon: ReactNode;
  children?: ReactNode;
};

export function TokenStatusScreen({ title, subtitle, icon, children }: TokenStatusScreenProps) {
  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <AuthCard title={title} subtitle={subtitle} icon={icon} backToLogin={false}>
        {children ?? <></>}
      </AuthCard>
    </AuthLayout>
  );
}

type LinkStateScreenProps = {
  title?: string;
  subtitle?: string;
  children?: ReactNode;
};

export function CheckingLinkScreen({ title, subtitle }: LinkStateScreenProps) {
  const t = useTranslations('auth.tokenStatus');

  return (
    <TokenStatusScreen
      title={title ?? t('checkingTitle')}
      subtitle={subtitle ?? t('checkingSubtitle')}
      icon={spinnerIcon}
    />
  );
}

export function ExpiredLinkScreen({ title, subtitle, children }: LinkStateScreenProps) {
  const t = useTranslations('auth.tokenStatus');

  return (
    <TokenStatusScreen
      title={title ?? t('expiredTitle')}
      subtitle={subtitle ?? t('expiredSubtitle')}
      icon={<div className="text-[32px]">⏳</div>}
    >
      {children}
    </TokenStatusScreen>
  );
}

export function AlreadyUsedLinkScreen({ title, subtitle, children }: LinkStateScreenProps) {
  const t = useTranslations('auth.tokenStatus');

  return (
    <TokenStatusScreen
      title={title ?? t('alreadyUsedTitle')}
      subtitle={subtitle ?? t('alreadyUsedSubtitle')}
      icon={<div className="text-[32px]">✅</div>}
    >
      {children}
    </TokenStatusScreen>
  );
}

/** The platform could not be reached, so nothing is known about the link. */
export function UnavailableLinkScreen() {
  const t = useTranslations('auth.tokenStatus');

  return (
    <TokenStatusScreen
      title={t('unavailableTitle')}
      subtitle={t('unavailableSubtitle')}
      icon={<div className="text-[32px]">🔌</div>}
    />
  );
}

export function InvalidLinkScreen({ title, subtitle, children }: LinkStateScreenProps) {
  const t = useTranslations('auth.tokenStatus');

  return (
    <TokenStatusScreen
      title={title ?? t('invalidTitle')}
      subtitle={subtitle ?? t('invalidSubtitle')}
      icon={<div className="text-[32px]">❌</div>}
    >
      {children}
    </TokenStatusScreen>
  );
}

type ResendLinkActionProps = {
  label?: string;
  onResend: () => void;
  isResending?: boolean;
  cooldownSeconds?: number;
  error?: string | null;
};

export function ResendLinkAction({
  label,
  onResend,
  isResending = false,
  cooldownSeconds = 0,
  error,
}: ResendLinkActionProps) {
  const t = useTranslations('auth.tokenStatus');

  return (
    <div className="flex flex-col items-center gap-4">
      <Button
        type="button"
        isLoading={isResending}
        disabled={cooldownSeconds > 0}
        onClick={onResend}
      >
        {label ?? t('requestNewLink')}
        {cooldownSeconds > 0 ? ` (${formatCountdown(cooldownSeconds)})` : ''}
      </Button>
      {error && (
        <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-sm text-error">
          {error}
        </p>
      )}
    </div>
  );
}

export function LinkStateAction({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Button type="button" onClick={onClick}>
      {label}
    </Button>
  );
}
