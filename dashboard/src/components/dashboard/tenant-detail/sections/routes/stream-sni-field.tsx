'use client';

import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  fieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { useValidationText } from '@/hooks/i18n/use-field-error';
import type { StreamRouteFormInput } from '@/schemas/stream-route-schemas';

type StreamSniFieldProps = {
  control: Control<StreamRouteFormInput>;
  errors: FieldErrors<StreamRouteFormInput>;
  isSubmitting: boolean;
  setValue: UseFormSetValue<StreamRouteFormInput>;
};

/**
 * Which handshakes the port answers.
 *
 * A client that sends no server name matches only an unrestricted port —
 * omitting it is free, so a restriction a missing name satisfied would not be
 * one.
 */
export function StreamSniField({ control, errors, isSubmitting, setValue }: StreamSniFieldProps) {
  const t = useTranslations('dashboard.ports.sni');
  const validationText = useValidationText();
  const names = useWatch({ control, name: 'sniNames' }) ?? [];

  function update(index: number, value: string) {
    setValue(
      'sniNames',
      names.map((name, current) => (current === index ? value : name)),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('title')}</span>
        <button
          type="button"
          className={addButtonClassName}
          disabled={isSubmitting}
          onClick={() =>
            setValue('sniNames', [...names, ''], { shouldDirty: true, shouldValidate: true })
          }
        >
          {t('add')}
        </button>
      </div>

      {names.length === 0 ? (
        <p className="text-xs text-textGray">{t('none')}</p>
      ) : (
        names.map((name, index) => (
          <div key={index} className="flex items-start gap-2">
            <Input
              placeholder="db.acme.com"
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              value={name}
              disabled={isSubmitting}
              onChange={(event) => update(index, event.target.value)}
            />
            <button
              type="button"
              className={removeButtonClassName}
              disabled={isSubmitting}
              onClick={() =>
                setValue(
                  'sniNames',
                  names.filter((_, current) => current !== index),
                  { shouldDirty: true, shouldValidate: true },
                )
              }
              aria-label={t('remove')}
            >
              <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                close
              </span>
            </button>
          </div>
        ))
      )}

      {typeof errors.sniNames?.message === 'string' ? (
        <p className="text-xs text-error">{validationText(errors.sniNames.message)}</p>
      ) : null}
    </div>
  );
}
