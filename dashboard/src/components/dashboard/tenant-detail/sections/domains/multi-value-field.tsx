'use client';

import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  fieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-field-styles';
import { DNS_RECORD_VALUE_PLACEHOLDERS } from '@/constants/dns-record';
import type { DnsRecordType } from '@/types/dns-record';

type MultiValueFieldProps = {
  isMultiline?: boolean;
  onChange: (values: string[]) => void;
  recordType: DnsRecordType;
  values: string[];
};

export function MultiValueField({
  isMultiline = false,
  onChange,
  recordType,
  values,
}: MultiValueFieldProps) {
  const t = useTranslations('dashboard.domains.dns.fields');
  const placeholder = DNS_RECORD_VALUE_PLACEHOLDERS[recordType] ?? t('value');

  function addValue() {
    onChange([...values, '']);
  }

  function updateValue(index: number, value: string) {
    onChange(values.map((current, currentIndex) => (currentIndex === index ? value : current)));
  }

  function removeValue(index: number) {
    onChange(values.filter((_, currentIndex) => currentIndex !== index));
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('values')}</span>
        <button type="button" className={addButtonClassName} onClick={addValue}>
          {t('addValue')}
        </button>
      </div>
      {values.map((value, index) =>
        isMultiline ? (
          <div key={index} className="flex items-start gap-2">
            <textarea
              value={value}
              placeholder={placeholder}
              rows={2}
              onChange={(event) => updateValue(index, event.target.value)}
              className="h-16 w-full resize-none rounded-lg border border-borderGray bg-cardBg px-2.5 py-2 text-sm text-white outline-none transition placeholder-textGray focus:border-focus"
            />
            {values.length > 1 ? (
              <button
                type="button"
                aria-label={t('removeValue')}
                className={removeButtonClassName}
                onClick={() => removeValue(index)}
              >
                <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                  close
                </span>
              </button>
            ) : null}
          </div>
        ) : (
          <div key={index} className="flex items-start gap-2">
            <Input
              value={value}
              placeholder={placeholder}
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              onChange={(event) => updateValue(index, event.target.value)}
            />
            {values.length > 1 ? (
              <button
                type="button"
                aria-label={t('removeValue')}
                className={removeButtonClassName}
                onClick={() => removeValue(index)}
              >
                <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                  close
                </span>
              </button>
            ) : null}
          </div>
        ),
      )}
    </div>
  );
}
