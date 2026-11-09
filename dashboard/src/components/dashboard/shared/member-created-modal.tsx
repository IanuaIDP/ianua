'use client';

import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { Tooltip } from '@/components/ui/tooltip';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import type { CreatedMemberCredentials } from '@/types/member';

export type MemberCreatedField = {
  action?: {
    icon?: string;
    isLoading?: boolean;
    label: string;
    onClick: () => void;
  };
  isCopyable?: boolean;
  label: string;
  tooltipSide?: 'bottom-left' | 'top-left' | 'left';
  value: string;
};

type MemberCreatedModalProps = {
  credentials?: CreatedMemberCredentials | null;
  description?: string;
  fields?: MemberCreatedField[];
  footer?: ReactNode;
  onClose: () => void;
  open?: boolean;
  signInPath?: string;
  title?: string;
};

type CredentialRowProps = {
  action?: MemberCreatedField['action'];
  isCopyable?: boolean;
  label: string;
  onCopy: (value: string) => void;
  tooltipSide?: 'bottom-left' | 'top-left' | 'left';
  value: string;
};

function CredentialRow({
  action,
  isCopyable = true,
  label,
  onCopy,
  tooltipSide = 'top-left',
  value,
}: CredentialRowProps) {
  const t = useTranslations('dashboard.memberCreated');

  return (
    <div className="flex items-center justify-between gap-4 border-b border-borderGray px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="text-xs font-medium text-textGray">{label}</p>
        <p className="mt-1 break-all text-sm font-medium text-white">{value}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {action ? (
          <>
            <button
              type="button"
              disabled={action.isLoading}
              onClick={(event) => {
                event.currentTarget.blur();
                action.onClick();
              }}
              className="flex items-center gap-1 text-xs font-semibold text-focus transition hover:text-focus/80 disabled:pointer-events-none disabled:opacity-60"
            >
              <span className="material-symbols-rounded text-base!">
                {action.icon ?? 'autorenew'}
              </span>
              {action.label}
            </button>
            {isCopyable ? <span className="h-5 w-px bg-borderGray" aria-hidden="true" /> : null}
          </>
        ) : null}
        {isCopyable ? (
          <Tooltip content={t('copy', { label })} side={tooltipSide}>
            <button
              type="button"
              aria-label={t('copy', { label })}
              onClick={(event) => {
                event.currentTarget.blur();
                onCopy(value);
              }}
              className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
            >
              <span className="material-symbols-rounded">content_copy</span>
            </button>
          </Tooltip>
        ) : null}
      </div>
    </div>
  );
}

export function MemberCreatedModal({
  credentials,
  description,
  fields,
  footer,
  onClose,
  open,
  signInPath = '/login',
  title,
}: MemberCreatedModalProps) {
  const t = useTranslations('dashboard.memberCreated');
  const copy = useCopyToClipboard();
  const signInUrl = useMemo(() => {
    if (typeof window === 'undefined') {
      return signInPath;
    }

    return `${window.location.origin}${signInPath}`;
  }, [signInPath]);
  const resolvedFields: MemberCreatedField[] =
    fields ??
    (credentials
      ? [
          { label: t('signInUrl'), tooltipSide: 'bottom-left', value: signInUrl },
          { label: t('email'), value: credentials.email },
          { label: t('password'), value: credentials.password },
        ]
      : []);
  const isOpen = open ?? Boolean(credentials);
  const copyAllText = resolvedFields.map((field) => `${field.label}: ${field.value}`).join('\n');
  const resolvedFooter =
    footer ??
    (credentials ? (
      <div className="flex items-center gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium h-6.5 text-orange">
        <span className="material-symbols-rounded text-sm!">warning</span>
        {t('copyWarning')}
      </div>
    ) : null);

  function copyToClipboard(value: string) {
    return copy(value, t('copied'));
  }

  return (
    <Modal
      open={isOpen}
      onClose={onClose}
      autoFocus={false}
      dismissible={false}
      title={title ?? t('title')}
      description={description ?? t('description')}
      icon={
        <span className="flex size-9 items-center justify-center rounded-full border-2 border-primary text-primary">
          <span className="material-symbols-rounded text-2xl!">check</span>
        </span>
      }
      primaryActionLabel={t('done')}
      onPrimaryAction={onClose}
      secondaryActionLabel={t('copyAll')}
      onSecondaryAction={() => void copyToClipboard(copyAllText)}
      showCloseButton={false}
    >
      <div className="overflow-hidden rounded-xl border border-borderGray">
        {resolvedFields.map((field) => (
          <CredentialRow
            key={field.label}
            action={field.action}
            isCopyable={field.isCopyable}
            label={field.label}
            tooltipSide={field.tooltipSide}
            value={field.value}
            onCopy={(value) => void copyToClipboard(value)}
          />
        ))}
      </div>

      {resolvedFooter}
    </Modal>
  );
}
