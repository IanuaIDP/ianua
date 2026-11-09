'use client';

import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';

type AuthConfigHeaderProps = {
  description: string;
  isDirty: boolean;
  isLoading: boolean;
  isSaving: boolean;
  onDiscard: () => void;
  submitDisabled?: boolean;
  title: string;
};

export function AuthConfigHeader({
  description,
  isDirty,
  isLoading,
  isSaving,
  onDiscard,
  submitDisabled,
  title,
}: AuthConfigHeaderProps) {
  const t = useTranslations('dashboard.settings.authConfig');

  return (
    <div className="flex shrink-0 flex-col gap-4 border-b border-borderGray px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-lg font-bold leading-6 text-white">{title}</h1>
        <p className="mt-1 text-xs font-medium text-textGray">{description}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={isLoading || !isDirty || isSaving}
          onClick={onDiscard}
          className="w-auto border-borderGray bg-surfaceChip px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBg"
        >
          {t('discard')}
        </Button>
        <Button
          type="submit"
          isLoading={isSaving}
          disabled={submitDisabled || isLoading || !isDirty}
          className="w-auto bg-focus px-4 py-1.5 font-medium tracking-normal text-white hover:bg-hoverBgPurple"
        >
          {t('save')}
        </Button>
      </div>
    </div>
  );
}
