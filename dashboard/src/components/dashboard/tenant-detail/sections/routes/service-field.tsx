'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';

import { useValidationText } from '@/hooks/i18n/use-field-error';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage, getTenantServices } from '@/lib/api';
import type { RouteFormInput } from '@/schemas/route-schemas';
import { cn } from '@/utils/cn';

type ServiceFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  orgSlug?: string;
  setValue: UseFormSetValue<RouteFormInput>;
  tenantSlug?: string;
};

/**
 * Picks the service a route forwards to.
 *
 * The address, timeout, backends and probe settings live on the service, so
 * twenty routes to one backend share one definition of it — and one view of
 * whether it is healthy. Moving a backend is then one edit in one place rather
 * than twenty edits that have to land together.
 */
export function ServiceField({
  control,
  errors,
  isSubmitting,
  orgSlug,
  setValue,
  tenantSlug,
}: ServiceFieldProps) {
  const t = useTranslations('dashboard.routes.fields.service');
  const tStatus = useLooseTranslations('dashboard.status');
  const validationText = useValidationText();
  const policyKind = useWatch({ control, name: 'policyKind' });
  const serviceId = useWatch({ control, name: 'serviceId' });

  const {
    data: services,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantServices(orgSlug ?? '', tenantSlug ?? '', { limit: 100 }),
    queryKey: ['tenant-services', orgSlug, tenantSlug, 'route-service'],
  });

  const items = services?.items ?? [];

  function choose(id: string) {
    setValue('serviceId', id, { shouldDirty: true, shouldValidate: true });
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <span className="text-xs font-semibold text-white">{t('title')}</span>
        <span className="text-xs text-textGray">{t('description')}</span>
      </div>

      {isLoading ? (
        <p className="text-xs text-textGray">{t('loading')}</p>
      ) : error ? (
        <p className="text-xs text-error">{getApiErrorMessage(error, t('loadFailed'))}</p>
      ) : items.length === 0 ? (
        <p className="text-xs text-textGray">{t('none')}</p>
      ) : (
        <div className="max-h-48 overflow-y-auto rounded-lg border border-borderGray">
          {items.map((service, index) => {
            const isSelected = service.id === serviceId;
            const backendCount = service.additionalBackends.length + 1;

            return (
              <button
                key={service.id}
                type="button"
                disabled={isSubmitting}
                onClick={() => choose(service.id)}
                className={cn(
                  'flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left transition',
                  index > 0 && 'border-t border-borderGray',
                  isSelected ? 'bg-focus/10' : 'hover:bg-hoverBg',
                )}
              >
                <span className="min-w-0">
                  <span
                    className={cn(
                      'block truncate text-xs font-medium',
                      isSelected ? 'text-focus' : 'text-white',
                    )}
                  >
                    {service.name}
                  </span>
                  <span className="mt-0.5 block truncate text-[10px] text-textGray">
                    {service.discoveryName || service.upstreamUrl}
                    {backendCount > 1 ? ` · ${t('backends', { count: backendCount })}` : ''}
                  </span>
                </span>
                <span className="flex items-center gap-2">
                  {service.status === 'Active' ? null : (
                    <span className="text-[10px] font-semibold text-orange">
                      {t('refuses', {
                        status: tStatus.has(service.status)
                          ? tStatus(service.status)
                          : service.status,
                      })}
                    </span>
                  )}
                  {policyKind !== 'Public' && !service.expectedAudience ? (
                    <span className="text-[10px] font-semibold text-orange">{t('noAudience')}</span>
                  ) : null}
                  {isSelected ? (
                    <span className="material-symbols-rounded text-base! text-focus">check</span>
                  ) : null}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {errors.serviceId ? (
        <p className="text-xs text-error">{validationText(errors.serviceId.message)}</p>
      ) : (
        <p className="text-xs text-textGray">
          {policyKind === 'Public' ? t('hintPublic') : t('hintAuthenticated')}
        </p>
      )}
    </div>
  );
}
