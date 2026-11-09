'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  fieldClassName,
  numberFieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-field-styles';
import type { MxRecordValue } from '@/types/dns-record';
import { cn } from '@/utils/cn';
import { emptyMxValue } from '@/utils/dns-record';

type MxValuesFieldProps = {
  onChange: (values: MxRecordValue[]) => void;
  values: MxRecordValue[];
};

export function MxValuesField({ onChange, values }: MxValuesFieldProps) {
  const t = useTranslations('dashboard.domains.dns.fields');

  function update(index: number, next: Partial<MxRecordValue>) {
    onChange(
      values.map((value, currentIndex) => (currentIndex === index ? { ...value, ...next } : value)),
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('mailServers')}</span>
        <button
          type="button"
          className={addButtonClassName}
          onClick={() => onChange([...values, emptyMxValue()])}
        >
          {t('addMailServer')}
        </button>
      </div>
      <p className="text-xs text-textGray">{t('mxHint')}</p>
      {values.map((value, index) => (
        <div key={index} className="flex items-start gap-2">
          <Input
            value={value.priority}
            type="number"
            placeholder="10"
            hint={index === 0 ? t('priority') : undefined}
            containerClassName="mb-0 w-20"
            className={numberFieldClassName}
            onChange={(event) => update(index, { priority: event.target.value })}
          />
          <Input
            value={value.host}
            placeholder="mail.acme.com"
            hint={index === 0 ? t('host') : undefined}
            containerClassName="mb-0 flex-1"
            className={fieldClassName}
            onChange={(event) => update(index, { host: event.target.value })}
          />
          {values.length > 1 ? (
            <button
              type="button"
              aria-label={t('removeMailServer')}
              className={cn(removeButtonClassName, index === 0 && 'mt-6')}
              onClick={() => onChange(values.filter((_, currentIndex) => currentIndex !== index))}
            >
              <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                close
              </span>
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}
