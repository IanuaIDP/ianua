'use client';

import { useState } from 'react';
import { useLocale, useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { Tooltip } from '@/components/ui/tooltip';
import { TryAccessPanel } from '@/components/dashboard/tenant-detail/sections/agents/delegations/try-access-panel';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';

export type GrantedAccess = {
  expiresAt: string;
  taskToken: string;
};

type AccessGrantedModalProps = {
  agentName?: string;
  granted: GrantedAccess | null;
  gatewayHosts: string[];
  onClose: () => void;
};

/// The end of the flow, which used to be a toast and nothing else.
///
/// Granting mints a task token — the credential the agent presents on every
/// request — and it is returned once, at this moment, and never again by any
/// listing. It was being discarded, so someone could complete the whole flow
/// correctly and still have nothing to give the thing they were configuring.
export function AccessGrantedModal({
  agentName,
  granted,
  gatewayHosts,
  onClose,
}: AccessGrantedModalProps) {
  const t = useTranslations('dashboard.delegations.grantedModal');
  const locale = useLocale();
  const copy = useCopyToClipboard();
  const [isSaved, setIsSaved] = useState(false);

  function handleClose() {
    setIsSaved(false);
    onClose();
  }

  async function handleCopy() {
    if (!granted) {
      return;
    }

    await copy(granted.taskToken, t('tokenCopied'));
    setIsSaved(true);
  }

  const expires = granted ? new Date(granted.expiresAt) : null;

  // The tenant's own verified domain when it has one. A placeholder only when
  // there is genuinely nothing to name — a plausible-looking URL that turns out
  // to be wrong costs more than an obvious blank does.
  const host = gatewayHosts[0] ?? 'YOUR-GATEWAY-HOST';
  const snippet = granted
    ? `curl https://${host}/your/route \\\n  -H "Authorization: Bearer ${granted.taskToken}"`
    : '';

  async function handleCopySnippet() {
    if (!snippet) {
      return;
    }

    await copy(snippet, t('exampleCopied'));
    setIsSaved(true);
  }

  return (
    <Modal
      open={Boolean(granted)}
      onClose={handleClose}
      dismissible={false}
      title={t('title')}
      description={t('description', { name: agentName ?? t('agentFallback') })}
      showCloseButton={false}
      primaryActionLabel={isSaved ? t('done') : t('copyFirst')}
      isPrimaryActionDisabled={!isSaved}
      onPrimaryAction={handleClose}
      showCancelButton={false}
    >
      <div className="flex items-center gap-2 rounded-lg border border-orange/50 bg-orange/10 px-3 py-1 text-[10px] font-medium text-orange">
        <span className="material-symbols-rounded text-sm!" aria-hidden>
          warning
        </span>
        <span>{t('shownOnce')}</span>
      </div>

      <div className="mt-3 flex items-center justify-between gap-4 rounded-lg border border-borderGray px-4 py-3">
        <pre className="max-h-48 min-w-0 flex-1 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] leading-relaxed text-white">
          {granted?.taskToken}
        </pre>
        <Tooltip content={t('copyToken')} side="top-left">
          <button
            type="button"
            aria-label={t('copyToken')}
            onClick={(event) => {
              event.currentTarget.blur();
              void handleCopy();
            }}
            className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
          >
            <span className="material-symbols-rounded">content_copy</span>
          </button>
        </Tooltip>
      </div>

      <div className="mt-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray">
            {t('usingIt')}
          </p>
          <button
            type="button"
            onClick={(event) => {
              event.currentTarget.blur();
              void handleCopySnippet();
            }}
            className="flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium text-textGray transition hover:bg-hoverBg hover:text-white"
          >
            <span className="material-symbols-rounded text-sm!" aria-hidden>
              content_copy
            </span>
            {t('copyExample')}
          </button>
        </div>
        <pre className="mt-1.5 overflow-x-auto rounded-lg border border-borderGray bg-surfaceChip px-3 py-2 font-mono text-[10px] leading-relaxed text-white">
          {snippet}
        </pre>
        <p className="mt-1.5 text-[10px] leading-snug text-textGray">
          {gatewayHosts.length ? t('usingHint') : t('usingHintNoHost')}
        </p>
      </div>

      {granted && gatewayHosts.length ? (
        <TryAccessPanel hosts={gatewayHosts} token={granted.taskToken} />
      ) : null}

      {expires ? (
        <p className="mt-3 text-[10px] leading-snug text-textGray">
          {t('expiresNote', { time: expires.toLocaleString(locale) })}
        </p>
      ) : null}
    </Modal>
  );
}
