'use client';

import { useTranslations } from 'next-intl';

import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import { cn } from '@/utils/cn';

type TwoFactorAuthenticationCardProps = {
  isBeginningMfa: boolean;
  isLoadingStatus?: boolean;
  isMfaEnabled: boolean;
  onDisableMfa?: () => void;
  onEnableMfa: () => void;
  /** Set when the status could not be read: the button then offers nothing. */
  statusErrorMessage?: string;
};

export function TwoFactorAuthenticationCard({
  isBeginningMfa,
  isLoadingStatus = false,
  isMfaEnabled,
  onDisableMfa,
  onEnableMfa,
  statusErrorMessage,
}: TwoFactorAuthenticationCardProps) {
  const t = useTranslations('dashboard.settings.security');
  const buttonLabel = isMfaEnabled ? t('twoFactor.disable') : t('twoFactor.enable');

  return (
    <SettingsCard title={t('twoFactor.title')}>
      {statusErrorMessage ? (
        <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {statusErrorMessage}
        </p>
      ) : null}
      <div className="flex flex-col gap-4 rounded-lg border border-borderGray px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-bold text-white">{t('twoFactor.heading')}</h3>
          <p className="mt-2 text-xs font-medium text-textGray">{t('twoFactor.description')}</p>
        </div>

        <Button
          type="button"
          isLoading={isBeginningMfa}
          disabled={
            isBeginningMfa ||
            isLoadingStatus ||
            Boolean(statusErrorMessage) ||
            (isMfaEnabled && !onDisableMfa)
          }
          onClick={isMfaEnabled ? onDisableMfa : onEnableMfa}
          className={cn(
            'w-auto shrink-0 px-4 py-1.5 font-medium tracking-normal text-white',
            isMfaEnabled
              ? 'border border-borderGray bg-cardBg hover:bg-hoverBg'
              : 'bg-focus hover:bg-hoverBgPurple',
          )}
        >
          {isLoadingStatus ? t('loading') : buttonLabel}
        </Button>
      </div>
    </SettingsCard>
  );
}
