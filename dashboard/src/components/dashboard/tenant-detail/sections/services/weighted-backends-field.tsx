'use client';

import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import {
  addButtonClassName,
  fieldClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import type { ServiceFormInput } from '@/schemas/service-schemas';

type WeightedBackendsFieldProps = {
  control: Control<ServiceFormInput>;
  errors: FieldErrors<ServiceFormInput>;
  isSubmitting: boolean;
  setValue: UseFormSetValue<ServiceFormInput>;
};

export function WeightedBackendsField({
  control,
  errors,
  isSubmitting,
  setValue,
}: WeightedBackendsFieldProps) {
  const t = useTranslations('dashboard.services.backends');
  const additionalBackends = useWatch({ control, name: 'additionalBackends' }) ?? [];

  function addBackend() {
    setValue('additionalBackends', [...additionalBackends, { url: '', weight: '100' }], {
      shouldDirty: true,
      shouldValidate: true,
    });
  }

  function updateBackend(index: number, field: 'url' | 'weight', value: string) {
    const next = additionalBackends.map((backend, current) =>
      current === index ? { ...backend, [field]: value } : backend,
    );

    setValue('additionalBackends', next, { shouldDirty: true, shouldValidate: true });
  }

  function removeBackend(index: number) {
    setValue(
      'additionalBackends',
      additionalBackends.filter((_, current) => current !== index),
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
          onClick={addBackend}
        >
          {t('add')}
        </button>
      </div>
      <p className="text-xs text-textGray">
        {additionalBackends.length === 0 ? t('none') : t('shared')}
      </p>
      {additionalBackends.length === 0
        ? null
        : additionalBackends.map((backend, index) => (
            <div key={index} className="flex items-start gap-2">
              <Input
                placeholder="http://canary.example.com"
                containerClassName="mb-0 flex-1"
                className={fieldClassName}
                value={backend.url}
                error={errors.additionalBackends?.[index]?.url}
                disabled={isSubmitting}
                onChange={(event) => updateBackend(index, 'url', event.target.value)}
              />
              <Input
                placeholder={t('weight')}
                containerClassName="mb-0 w-24"
                className={fieldClassName}
                value={backend.weight}
                error={errors.additionalBackends?.[index]?.weight}
                disabled={isSubmitting}
                onChange={(event) => updateBackend(index, 'weight', event.target.value)}
              />
              <button
                type="button"
                className={removeButtonClassName}
                disabled={isSubmitting}
                onClick={() => removeBackend(index)}
                aria-label={t('remove')}
              >
                <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                  close
                </span>
              </button>
            </div>
          ))}
    </div>
  );
}
