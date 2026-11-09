'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import type { HeaderEntry } from '@/types/pipeline';

type HeaderEntriesFieldProps = {
  entries: HeaderEntry[];
  hint?: string;
  isDisabled?: boolean;
  label: string;
  namePlaceholder: string;
  onChange: (entries: HeaderEntry[]) => void;
  valuePlaceholder: string;
};

export function HeaderEntriesField({
  entries,
  hint,
  isDisabled = false,
  label,
  namePlaceholder,
  onChange,
  valuePlaceholder,
}: HeaderEntriesFieldProps) {
  const t = useTranslations('dashboard.pipelines.addStage');
  function update(index: number, field: 'name' | 'value', value: string) {
    onChange(
      entries.map((entry, current) => (current === index ? { ...entry, [field]: value } : entry)),
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{label}</span>
        <button
          type="button"
          className={addButtonClassName}
          disabled={isDisabled}
          onClick={() => onChange([...entries, { name: '', value: '' }])}
        >
          {t('addEntry')}
        </button>
      </div>
      {entries.map((entry, index) => (
        <div key={index} className="flex items-start gap-2">
          <Input
            placeholder={namePlaceholder}
            containerClassName="mb-0 flex-1"
            className="bg-cardBg"
            value={entry.name}
            disabled={isDisabled}
            onChange={(event) => update(index, 'name', event.target.value)}
          />
          <Input
            placeholder={valuePlaceholder}
            containerClassName="mb-0 flex-1"
            className="bg-cardBg"
            value={entry.value}
            disabled={isDisabled}
            onChange={(event) => update(index, 'value', event.target.value)}
          />
          <button
            type="button"
            className={removeButtonClassName}
            disabled={isDisabled}
            onClick={() => onChange(entries.filter((_, current) => current !== index))}
            aria-label={t('removeEntry', { label })}
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              close
            </span>
          </button>
        </div>
      ))}
      {hint ? <p className="text-xs text-textGray">{hint}</p> : null}
    </div>
  );
}
