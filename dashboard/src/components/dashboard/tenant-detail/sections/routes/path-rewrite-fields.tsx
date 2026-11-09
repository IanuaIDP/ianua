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
import { useRouteOptions } from '@/hooks/dashboard/use-route-options';
import type { RouteFormInput } from '@/schemas/route-schemas';

type PathRewriteFieldsProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  register: UseFormRegister<RouteFormInput>;
};

/**
 * What the upstream sees instead of the path that arrived.
 *
 * A template builds the forwarded path out of the parameters the pattern
 * captured, so `/api/orders/{id}` can reach a backend that expects
 * `/v2/order/{id}` without the backend or the caller changing.
 */
export function PathRewriteFields({
  control,
  errors,
  isSubmitting,
  register,
}: PathRewriteFieldsProps) {
  const t = useTranslations('dashboard.routes.rewrite');
  const { pathRewriteOptions } = useRouteOptions();
  const pathRewriteMode = useWatch({ control, name: 'pathRewriteMode' });

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Controller
        control={control}
        name="pathRewriteMode"
        render={({ field }) => (
          <Select
            label={t('label')}
            placeholder={t('placeholder')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            options={pathRewriteOptions}
            value={field.value}
            error={errors.pathRewriteMode}
            onChange={field.onChange}
          />
        )}
      />
      {pathRewriteMode === 'template' ? (
        <Input
          label={t('template')}
          placeholder="/v2/order/{id}"
          hint={t('templateHint')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('pathRewriteTemplate')}
          error={errors.pathRewriteTemplate}
          disabled={isSubmitting}
        />
      ) : null}
    </div>
  );
}
