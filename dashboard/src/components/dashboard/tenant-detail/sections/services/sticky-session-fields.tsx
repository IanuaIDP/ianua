'use client';

import {
  Controller,
  useWatch,
  type Control,
  type FieldErrors,
  type UseFormRegister,
} from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { useServiceOptions } from '@/hooks/dashboard/use-service-options';
import type { ServiceFormInput } from '@/schemas/service-schemas';

type StickySessionFieldsProps = {
  control: Control<ServiceFormInput>;
  errors: FieldErrors<ServiceFormInput>;
  isSubmitting: boolean;
  register: UseFormRegister<ServiceFormInput>;
};

export function StickySessionFields({
  control,
  errors,
  isSubmitting,
  register,
}: StickySessionFieldsProps) {
  const t = useTranslations('dashboard.services.sticky');
  const { stickySessionOptions } = useServiceOptions();
  const stickySessionKind = useWatch({ control, name: 'stickySessionKind' });
  const needsValue = stickySessionKind === 'Cookie' || stickySessionKind === 'Header';

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Controller
        control={control}
        name="stickySessionKind"
        render={({ field }) => (
          <Select
            label={t('label')}
            placeholder={t('placeholder')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            options={stickySessionOptions}
            value={field.value}
            error={errors.stickySessionKind}
            onChange={field.onChange}
          />
        )}
      />
      {needsValue ? (
        <Input
          label={stickySessionKind === 'Cookie' ? t('cookieName') : t('headerName')}
          placeholder={stickySessionKind === 'Cookie' ? 'session_id' : 'X-Session-Id'}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('stickySessionValue')}
          error={errors.stickySessionValue}
          disabled={isSubmitting}
        />
      ) : null}
    </div>
  );
}
