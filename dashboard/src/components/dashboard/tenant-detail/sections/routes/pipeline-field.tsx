'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';

import { useValidationText } from '@/hooks/i18n/use-field-error';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage, getTenantPipelines } from '@/lib/api';
import type { RouteFormInput } from '@/schemas/route-schemas';
import { cn } from '@/utils/cn';

type PipelineFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  orgSlug?: string;
  setValue: UseFormSetValue<RouteFormInput>;
  tenantSlug?: string;
};

/**
 * Picks the pipeline a route runs.
 *
 * There is no default and nothing to fall back to. Editing a pipeline means
 * disabling it, and a disabled pipeline refuses every route running it — so a
 * pipeline change ships by building the replacement alongside the live one and
 * moving routes across, which only works if each route says which one it runs.
 *
 * Switching an existing route here is that move: it takes effect on the next
 * request, with no gap where the route runs nothing.
 */
export function PipelineField({
  control,
  errors,
  isSubmitting,
  orgSlug,
  setValue,
  tenantSlug,
}: PipelineFieldProps) {
  const t = useTranslations('dashboard.routes.fields.pipeline');
  const tStatus = useLooseTranslations('dashboard.status');
  const validationText = useValidationText();
  const pipelineId = useWatch({ control, name: 'pipelineId' });

  const {
    data: pipelines,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantPipelines(orgSlug ?? '', tenantSlug ?? ''),
    queryKey: ['tenant-pipelines', orgSlug, tenantSlug, 'route-pipeline'],
  });

  function choose(id: string) {
    setValue('pipelineId', id, { shouldDirty: true, shouldValidate: true });
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
      ) : (pipelines ?? []).length === 0 ? (
        <p className="text-xs text-textGray">{t('none')}</p>
      ) : (
        <div className="max-h-48 overflow-y-auto rounded-lg border border-borderGray">
          {(pipelines ?? []).map((pipeline, index) => {
            const isSelected = pipeline.id === pipelineId;

            return (
              <button
                key={pipeline.id}
                type="button"
                disabled={isSubmitting}
                onClick={() => choose(pipeline.id)}
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
                    {pipeline.name}
                  </span>
                  <span className="mt-0.5 block text-[10px] text-textGray">
                    {t('counts', {
                      routes: pipeline.routeCount,
                      stages: pipeline.stageCount,
                    })}
                  </span>
                </span>
                <span className="flex items-center gap-2">
                  {pipeline.status === 'Active' ? null : (
                    <span className="text-[10px] font-semibold text-orange">
                      {t('refuses', {
                        status: tStatus.has(pipeline.status)
                          ? tStatus(pipeline.status)
                          : pipeline.status,
                      })}
                    </span>
                  )}
                  {isSelected ? (
                    <span className="material-symbols-rounded text-base! text-focus">check</span>
                  ) : null}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {errors.pipelineId ? (
        <p className="text-xs text-error">{validationText(errors.pipelineId.message)}</p>
      ) : (
        <p className="text-xs text-textGray">{t('hint')}</p>
      )}
    </div>
  );
}
