'use client';

import { useTranslations } from 'next-intl';

type SigningKeyNoticeProps = {
  isPreparing: boolean;
  onPrepare: () => void;
};

/// The prerequisite nobody guesses.
///
/// A delegation's task token is signed with the tenant's key, so without one
/// the grant fails — several steps after the point where it could have been
/// fixed, with a message about signing keys that reads like an internal error.
/// Saying so here, with the fix attached, turns a dead end into a button.
export function SigningKeyNotice({ isPreparing, onPrepare }: SigningKeyNoticeProps) {
  const t = useTranslations('dashboard.delegations.signingKey');

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-orange/50 bg-orange/10 p-3">
      <div className="flex items-start gap-2">
        <span className="material-symbols-rounded text-sm! text-orange" aria-hidden>
          key
        </span>
        <div className="flex flex-col gap-0.5">
          <p className="text-xs font-medium text-orange">{t('title')}</p>
          <p className="text-xs leading-snug text-textGray">{t('description')}</p>
        </div>
      </div>
      <button
        type="button"
        disabled={isPreparing}
        onClick={onPrepare}
        className="self-start rounded-md bg-orange/20 px-2.5 py-1 text-xs font-semibold text-orange transition hover:bg-orange/30 disabled:opacity-60"
      >
        {isPreparing ? t('creating') : t('create')}
      </button>
    </div>
  );
}
