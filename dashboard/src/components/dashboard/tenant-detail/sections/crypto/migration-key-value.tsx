import { useTranslations } from 'next-intl';

type MigrationKeyValueProps = {
  label: string;
  onCopy?: () => void;
  value: string;
};

export function MigrationKeyValue({ label, onCopy, value }: MigrationKeyValueProps) {
  const t = useTranslations('dashboard.crypto');

  return (
    <div className="flex h-full min-w-0 flex-col justify-between p-4">
      <span className="text-[10px] font-semibold text-textGray">{label}</span>
      <div className="flex min-w-0 items-center gap-2">
        <span className="truncate text-xs font-semibold text-white">{value}</span>
        {onCopy ? (
          <button
            type="button"
            aria-label={t('copyLabel', { label })}
            onClick={onCopy}
            className="flex size-5 shrink-0 items-center justify-center rounded text-textGray transition hover:text-white"
          >
            <span className="material-symbols-rounded text-base!" aria-hidden="true">
              content_copy
            </span>
          </button>
        ) : null}
      </div>
    </div>
  );
}
