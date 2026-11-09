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

type CustomPermissionsFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  setValue: UseFormSetValue<RouteFormInput>;
};

export function CustomPermissionsField({
  control,
  errors,
  isSubmitting,
  setValue,
}: CustomPermissionsFieldProps) {
  const t = useTranslations('dashboard.routes.fields');
  const validationText = useValidationText();
  const customPermissions = useWatch({ control, name: 'customPermissions' }) ?? [];

  function addPermission() {
    setValue('customPermissions', [...customPermissions, { action: '', resource: '' }], {
      shouldDirty: true,
      shouldValidate: true,
    });
  }

  function updatePermission(index: number, field: 'action' | 'resource', value: string) {
    const next = customPermissions.map((permission, current) =>
      current === index ? { ...permission, [field]: value } : permission,
    );

    setValue('customPermissions', next, { shouldDirty: true, shouldValidate: true });
  }

  function removePermission(index: number) {
    setValue(
      'customPermissions',
      customPermissions.filter((_, current) => current !== index),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">{t('customPermissions')}</span>
        <button
          type="button"
          className={addButtonClassName}
          disabled={isSubmitting}
          onClick={addPermission}
        >
          {t('addPermission')}
        </button>
      </div>
      {customPermissions.length === 0 ? (
        <p className="text-xs text-textGray">{t('noCustomPermissions')}</p>
      ) : (
        customPermissions.map((permission, index) => (
          <div key={index} className="flex items-start gap-2">
            <Input
              placeholder={t('resource')}
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              value={permission.resource}
              error={errors.customPermissions?.[index]?.resource}
              disabled={isSubmitting}
              onChange={(event) => updatePermission(index, 'resource', event.target.value)}
            />
            <Input
              placeholder={t('action')}
              containerClassName="mb-0 flex-1"
              className={fieldClassName}
              value={permission.action}
              error={errors.customPermissions?.[index]?.action}
              disabled={isSubmitting}
              onChange={(event) => updatePermission(index, 'action', event.target.value)}
            />
            <button
              type="button"
              className={removeButtonClassName}
              disabled={isSubmitting}
              onClick={() => removePermission(index)}
              aria-label={t('removePermission')}
            >
              <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                close
              </span>
            </button>
          </div>
        ))
      )}
      {typeof errors.customPermissions?.message === 'string' ? (
        <p className="text-xs text-error">{validationText(errors.customPermissions.message)}</p>
      ) : null}
    </div>
  );
}
