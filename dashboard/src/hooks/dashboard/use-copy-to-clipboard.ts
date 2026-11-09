'use client';

import { useTranslations } from 'next-intl';

import { useNotification } from '@/components/ui/notifications';
import { writeToClipboard } from '@/utils/clipboard';

/** Copies a value and tells the person whether it reached the clipboard. */
export function useCopyToClipboard() {
  const t = useTranslations('common');
  const { showNotification } = useNotification();

  return async function copy(value: string, successMessage: string) {
    const isCopied = await writeToClipboard(value);

    showNotification(
      isCopied
        ? { message: successMessage, type: 'default' }
        : { message: t('copyFailed'), type: 'error' },
    );

    return isCopied;
  };
}
