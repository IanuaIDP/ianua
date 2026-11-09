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
import type { RouteFormInput } from '@/schemas/route-schemas';

type ScopesFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  setValue: UseFormSetValue<RouteFormInput>;
};

export function ScopesField({ control, errors, isSubmitting, setValue }: ScopesFieldProps) {
  const t = useTranslations('dashboard.routes.fields');
  const validationText = useValidationText();
  const scopes = useWatch({ control, name: 'scopes' }) ?? [];

  function addScope() {
    setValue('scopes', [...scopes, ''], { shouldDirty: true, shouldValidate: true });
  }

  function updateScope(index: number, value: string) {
    const next = scopes.map((scope, current) => (current === index ? value : scope));

    setValue('scopes', next, { shouldDirty: true, shouldValidate: true });
  }

  function removeScope(index: number) {
    setValue(
      'scopes',
      scopes.filter((_, current) => current !== index),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('scopes')}</span>
        <button
          type="button"
          className={addButtonClassName}
          disabled={isSubmitting}
          onClick={addScope}
        >
          {t('addScope')}
        </button>
      </div>
      {scopes.length === 0 ? (
        <p className="text-xs text-textGray">{t('noScopes')}</p>
      ) : (
        scopes.map((scope, index) => (
          <div key={index} className="flex items-start gap-2">
            <Input
              placeholder="resource:action"
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              value={scope}
              error={errors.scopes?.[index]}
              disabled={isSubmitting}
              onChange={(event) => updateScope(index, event.target.value)}
            />
            <button
              type="button"
              className={removeButtonClassName}
              disabled={isSubmitting}
              onClick={() => removeScope(index)}
              aria-label={t('removeScope')}
            >
              <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                close
              </span>
            </button>
          </div>
        ))
      )}
      {typeof errors.scopes?.message === 'string' ? (
        <p className="text-xs text-error">{validationText(errors.scopes.message)}</p>
      ) : null}
    </div>
  );
}
