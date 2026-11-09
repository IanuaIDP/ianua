'use client';

import { useTranslations } from 'next-intl';

import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  addButtonClassName,
  fieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-field-styles';
import { CAA_TAGS } from '@/constants/dns-record';
import type { CaaRecordValue } from '@/types/dns-record';
import { emptyCaaValue } from '@/utils/dns-record';

type CaaValuesFieldProps = {
  onChange: (values: CaaRecordValue[]) => void;
  values: CaaRecordValue[];
};

export function CaaValuesField({ onChange, values }: CaaValuesFieldProps) {
  const t = useTranslations('dashboard.domains.dns.fields');
  const tagOptions = CAA_TAGS.map((tag) => ({ label: t(`caaTags.${tag}`), value: tag }));

  function update(index: number, next: Partial<CaaRecordValue>) {
    onChange(
      values.map((value, currentIndex) => (currentIndex === index ? { ...value, ...next } : value)),
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('issuers')}</span>
        <button
          type="button"
          className={addButtonClassName}
          onClick={() => onChange([...values, emptyCaaValue()])}
        >
          {t('addIssuer')}
        </button>
      </div>
      {values.map((value, index) => (
        <div key={index} className="flex flex-col gap-2 rounded-lg border border-borderGray p-3">
          <div className="grid grid-cols-2 gap-2">
            <Select
              label={index === 0 ? t('tag') : undefined}
              containerClassName="mb-0"
              className={fieldClassName}
              options={tagOptions}
              value={value.tag}
              onChange={(nextTag) => update(index, { tag: nextTag as CaaRecordValue['tag'] })}
            />
            <Input
              label={index === 0 ? t('value') : undefined}
              value={value.value}
              placeholder={value.tag === 'iodef' ? 'mailto:security@acme.com' : 'letsencrypt.org'}
              containerClassName="mb-0"
              className={fieldClassName}
              onChange={(event) => update(index, { value: event.target.value })}
            />
          </div>
          <div className="flex items-center justify-between">
            <Checkbox
              checked={value.isCritical}
              label={t('critical')}
              onChange={(event) => update(index, { isCritical: event.target.checked })}
            />
            {values.length > 1 ? (
              <button
                type="button"
                aria-label={t('removeIssuer')}
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
