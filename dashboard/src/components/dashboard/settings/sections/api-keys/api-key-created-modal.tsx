'use client';

import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { Tooltip } from '@/components/ui/tooltip';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import type { CreatedApiKey } from '@/types/api-key';

type ApiKeyCreatedModalProps = {
  apiKey: CreatedApiKey | null;
  onClose: () => void;
};

export function ApiKeyCreatedModal({ apiKey, onClose }: ApiKeyCreatedModalProps) {
  const t = useTranslations('dashboard.settings.apiKeys');
  const copy = useCopyToClipboard();
  const apiKeyValue = apiKey?.key ?? '';

  function copyToClipboard(value: string) {
    return copy(value, t('created.copied'));
  }

  return (
    <Modal
      open={Boolean(apiKey)}
      onClose={onClose}
      autoFocus={false}
      dismissible={false}
      title={t('created.title')}
      description={t('created.description')}
      icon={
        <span className="flex size-9 items-center justify-center rounded-full border-2 border-primary text-primary">
          <span className="material-symbols-rounded text-2xl!">check</span>
        </span>
      }
      primaryActionLabel={t('created.done')}
      onPrimaryAction={onClose}
      showCloseButton={false}
      showCancelButton={false}
    >
      <div className="flex items-center justify-between gap-4 rounded-lg border border-borderGray px-4 py-3">
        <div className="min-w-0">
          <p className="text-xs font-medium text-textGray">{t('created.keyLabel')}</p>
          <p className="mt-1 break-all text-sm font-medium text-white">{apiKeyValue}</p>
        </div>
        <Tooltip content={t('created.copy')} side="top-left">
          <button
            type="button"
            aria-label={t('created.copy')}
            onClick={(event) => {
              event.currentTarget.blur();
              void copyToClipboard(apiKeyValue);
            }}
            className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
          >
            <span className="material-symbols-rounded">content_copy</span>
          </button>
        </Tooltip>
      </div>

      <div className="flex items-center gap-2 rounded-lg border border-orange/50 h-6.5 bg-orange/10 p-2.5 text-[10px] font-medium text-orange">
        <span className="material-symbols-rounded text-sm!">warning</span>
        {t('created.warning')}
      </div>
    </Modal>
  );
}
