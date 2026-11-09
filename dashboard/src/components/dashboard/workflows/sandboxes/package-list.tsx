'use client';

import { useFieldArray, type Control, type FormState, type UseFormRegister } from 'react-hook-form';
import { useTranslations } from 'next-intl';

import {
  addButtonClassName,
  fieldClassName,
  fieldContainerClassName,
  removeButtonClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import type { SandboxVersionFormInput } from '@/schemas/sandbox-schemas';

const MOST_PACKAGES = 50;

type PackageListProps = {
  control: Control<SandboxVersionFormInput>;
  errors: FormState<SandboxVersionFormInput>['errors'];
  register: UseFormRegister<SandboxVersionFormInput>;
};

/** The packages a version pins, each at one exact version. */
export function PackageList({ control, errors, register }: PackageListProps) {
  const t = useTranslations('dashboard.sandboxes.editor');
  const { append, fields, remove } = useFieldArray({ control, name: 'packages' });

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs font-semibold text-white">{t('packages')}</p>
      <p className="text-xs text-textGray">{t('packagesHint')}</p>
      {fields.map((field, index) => (
        <div key={field.id} className="flex items-start gap-2">
          <Input
            {...register(`packages.${index}.name`)}
            aria-label={t('packageName')}
            className={fieldClassName}
            containerClassName={`${fieldContainerClassName} flex-1`}
            error={errors.packages?.[index]?.name}
            placeholder={t('packageNamePlaceholder')}
          />
          <Input
            {...register(`packages.${index}.version`)}
            aria-label={t('packageVersion')}
            className={fieldClassName}
            containerClassName={`${fieldContainerClassName} w-32`}
            error={errors.packages?.[index]?.version}
            placeholder={t('packageVersionPlaceholder')}
          />
          <button
            aria-label={t('removePackage')}
            className={removeButtonClassName}
            type="button"
            onClick={() => remove(index)}
          >
            <span className="material-symbols-rounded text-sm!" aria-hidden>
              close
            </span>
          </button>
        </div>
      ))}
      {fields.length < MOST_PACKAGES ? (
        <button
          className={addButtonClassName}
          type="button"
          onClick={() => append({ name: '', version: '' })}
        >
          {t('addPackage')}
        </button>
      ) : null}
    </div>
  );
}
