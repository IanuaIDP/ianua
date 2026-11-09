'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  fieldClassName,
  numberFieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-field-styles';
import type { SrvRecordValue } from '@/types/dns-record';
import { emptySrvValue } from '@/utils/dns-record';

type SrvValuesFieldProps = {
  onChange: (values: SrvRecordValue[]) => void;
  values: SrvRecordValue[];
};

export function SrvValuesField({ onChange, values }: SrvValuesFieldProps) {
  const t = useTranslations('dashboard.domains.dns.fields');

  function update(index: number, next: Partial<SrvRecordValue>) {
    onChange(
      values.map((value, currentIndex) => (currentIndex === index ? { ...value, ...next } : value)),
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('serviceTargets')}</span>
        <button
          type="button"
          className={addButtonClassName}
          onClick={() => onChange([...values, emptySrvValue()])}
        >
          {t('addTarget')}
        </button>
      </div>
      <p className="text-xs text-textGray">{t('srvHint')}</p>
      {values.map((value, index) => (
        <div key={index} className="flex flex-col gap-2 rounded-lg border border-borderGray p-3">
          <div className="grid grid-cols-3 gap-2">
            <Input
              value={value.priority}
              type="number"
              placeholder="10"
              hint={index === 0 ? t('priority') : undefined}
              containerClassName="mb-0"
              className={numberFieldClassName}
              onChange={(event) => update(index, { priority: event.target.value })}
            />
            <Input
              value={value.weight}
              type="number"
              placeholder="5"
              hint={index === 0 ? t('weight') : undefined}
              containerClassName="mb-0"
              className={numberFieldClassName}
              onChange={(event) => update(index, { weight: event.target.value })}
            />
            <Input
              value={value.port}
              type="number"
              placeholder="443"
              hint={index === 0 ? t('port') : undefined}
              containerClassName="mb-0"
              className={numberFieldClassName}
              onChange={(event) => update(index, { port: event.target.value })}
            />
          </div>
          <div className="flex items-start gap-2">
            <Input
              value={value.host}
              placeholder="sip.acme.com"
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              onChange={(event) => update(index, { host: event.target.value })}
            />
            {values.length > 1 ? (
              <button
                type="button"
                aria-label={t('removeTarget')}
                className={removeButtonClassName}
                onClick={() => onChange(values.filter((_, currentIndex) => currentIndex !== index))}
              >
                <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                  close
                </span>
              </button>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}
