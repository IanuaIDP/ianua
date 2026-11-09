'use client';

import {
  Controller,
  useWatch,
  type Control,
  type FieldErrors,
  type UseFormRegister,
} from 'react-hook-form';
import { useTranslations } from 'next-intl';

import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { useServiceOptions } from '@/hooks/dashboard/use-service-options';
import type { ServiceFormInput } from '@/schemas/service-schemas';

type DiscoveryFieldsProps = {
  control: Control<ServiceFormInput>;
  errors: FieldErrors<ServiceFormInput>;
  isSubmitting: boolean;
  register: UseFormRegister<ServiceFormInput>;
};

/**
 * Backends named rather than listed.
 *
 * A service pointing at replicas that come and go cannot list them: an address
 * written down is one that eventually answers nothing, and a replica that
 * appears gets no traffic until somebody edits the service. With a name set,
 * the URL above becomes the fallback the proxy uses until the name first
 * resolves — and, for address records, the port those records do not carry.
 */
export function DiscoveryFields({ control, errors, isSubmitting, register }: DiscoveryFieldsProps) {
  const t = useTranslations('dashboard.services.discovery');
  const { discoveryKindOptions } = useServiceOptions();
  const discoveryEnabled = useWatch({ control, name: 'discoveryEnabled' });

  return (
    <div className="flex flex-col gap-3">
      <Checkbox label={t('enable')} {...register('discoveryEnabled')} disabled={isSubmitting} />

      {discoveryEnabled ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Input
            label={t('name')}
            placeholder="_http._tcp.orders.internal"
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('discoveryName')}
            error={errors.discoveryName}
            disabled={isSubmitting}
          />
          <Controller
            control={control}
            name="discoveryKind"
            render={({ field }) => (
              <Select
                label={t('recordType')}
                placeholder={t('recordTypePlaceholder')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={discoveryKindOptions}
                value={field.value}
                error={errors.discoveryKind}
                onChange={field.onChange}
              />
            )}
          />
          <Input
            label={t('refresh')}
            placeholder="30"
            type="number"
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            {...register('discoveryRefreshSecs')}
            error={errors.discoveryRefreshSecs}
            disabled={isSubmitting}
          />
        </div>
      ) : null}
    </div>
  );
}
