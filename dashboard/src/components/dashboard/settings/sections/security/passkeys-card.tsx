'use client';

import { useTranslations } from 'next-intl';

import { PasskeysTable } from '@/components/dashboard/settings/sections/security/passkeys-table';
import { SettingsCard } from '@/components/dashboard/settings/settings-card';
import { Button } from '@/components/ui/Button';
import type { Passkey } from '@/types/passkey';

type PasskeysCardProps = {
  errorMessage?: string | null;
  isLoading?: boolean;
  isRegistering?: boolean;
  isPasskeySupported?: boolean;
  onAddPasskeyClick: () => void;
  onRemoveConfirm: (passkey: Passkey) => Promise<void> | void;
  onRenameClick: (passkey: Passkey) => void;
  passkeys: Passkey[];
};

export function PasskeysCard({
  errorMessage,
  isLoading = false,
  isRegistering = false,
  isPasskeySupported = true,
  onAddPasskeyClick,
  onRemoveConfirm,
  onRenameClick,
  passkeys,
}: PasskeysCardProps) {
  const t = useTranslations('dashboard.settings.security');

  return (
    <SettingsCard
      title={t('passkeys.title')}
      description={t('passkeys.description')}
      className="overflow-hidden"
      headerAction={
        isPasskeySupported ? (
          <Button
            type="button"
            isLoading={isRegistering}
            disabled={isRegistering}
            onClick={onAddPasskeyClick}
            className="w-auto shrink-0 bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
          >
            {t('passkeys.add')}
          </Button>
        ) : null
      }
    >
      {errorMessage && (
        <p className="mb-4 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
          {errorMessage}
        </p>
      )}

      {isPasskeySupported ? (
        <div className="-mx-4 -mb-4">
          <PasskeysTable
            isLoading={isLoading}
            passkeys={passkeys}
            onRemoveConfirm={onRemoveConfirm}
            onRenameClick={onRenameClick}
          />
        </div>
      ) : (
        <p className="rounded-lg border border-borderGray px-4 py-3 text-xs font-medium text-textGray">
          {t('passkeys.unsupported')}
        </p>
      )}
    </SettingsCard>
  );
}
