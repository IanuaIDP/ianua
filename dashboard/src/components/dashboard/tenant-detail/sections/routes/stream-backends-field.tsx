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

type StreamBackendsFieldProps = {
  control: Control<StreamRouteFormInput>;
  errors: FieldErrors<StreamRouteFormInput>;
  isSubmitting: boolean;
  setValue: UseFormSetValue<StreamRouteFormInput>;
};

/**
 * Where a port forwards to.
 *
 * A host and a port rather than a URL — there is no scheme at layer 4. More
 * than one splits traffic by weight, the same way a service's weighted
 * backends do.
 */
export function StreamBackendsField({
  control,
  errors,
  isSubmitting,
  setValue,
}: StreamBackendsFieldProps) {
  const t = useTranslations('dashboard.ports.backends');
  const validationText = useValidationText();
  const backends = useWatch({ control, name: 'backends' }) ?? [];

  function update(index: number, field: 'host' | 'port' | 'weight', value: string) {
    setValue(
      'backends',
      backends.map((backend, current) =>
        current === index ? { ...backend, [field]: value } : backend,
      ),
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
            setValue('backends', [...backends, { host: '', port: '', weight: '1' }], {
              shouldDirty: true,
              shouldValidate: true,
            })
          }
        >
          {t('add')}
        </button>
      </div>

      {backends.map((backend, index) => (
        <div key={index} className="flex items-start gap-2">
          <Input
            placeholder="db.internal"
            containerClassName="mb-0 flex-1"
            className={fieldClassName}
            value={backend.host}
            error={errors.backends?.[index]?.host}
            disabled={isSubmitting}
            onChange={(event) => update(index, 'host', event.target.value)}
          />
          <Input
            placeholder={t('port')}
            containerClassName="mb-0 w-24"
            className={fieldClassName}
            value={backend.port}
            error={errors.backends?.[index]?.port}
            disabled={isSubmitting}
            onChange={(event) => update(index, 'port', event.target.value)}
          />
          <Input
            placeholder={t('weight')}
            containerClassName="mb-0 w-24"
            className={fieldClassName}
            value={backend.weight}
            error={errors.backends?.[index]?.weight}
            disabled={isSubmitting}
            onChange={(event) => update(index, 'weight', event.target.value)}
          />
          <button
            type="button"
            className={removeButtonClassName}
            disabled={isSubmitting || backends.length === 1}
            onClick={() =>
              setValue(
                'backends',
                backends.filter((_, current) => current !== index),
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
      ))}

      {typeof errors.backends?.message === 'string' ? (
        <p className="text-xs text-error">{validationText(errors.backends.message)}</p>
      ) : null}
    </div>
  );
}
