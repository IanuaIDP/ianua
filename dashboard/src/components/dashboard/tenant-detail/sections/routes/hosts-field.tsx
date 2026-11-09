'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';

import { Input } from '@/components/ui/Input';
import { useValidationText } from '@/hooks/i18n/use-field-error';
import { getApiErrorMessage, getTenantDomains } from '@/lib/api';
import type { RouteFormInput } from '@/schemas/route-schemas';
import { cn } from '@/utils/cn';

type HostsFieldProps = {
  control: Control<RouteFormInput>;
  errors: FieldErrors<RouteFormInput>;
  isSubmitting: boolean;
  orgSlug?: string;
  setValue: UseFormSetValue<RouteFormInput>;
  tenantSlug?: string;
};

const choiceClassName =
  'flex-1 rounded-lg border px-3 py-2 text-xs font-semibold transition disabled:pointer-events-none disabled:opacity-60';

/**
 * Picks which of the tenant's domains a route answers on.
 *
 * The choice is explicit rather than defaulted. An unrestricted route silently
 * widens every time a domain is added — register one next month and this route
 * starts answering there too — so "all domains" is something to select, not
 * something you get by leaving a field alone.
 *
 * Options are the tenant's verified domains because the API rejects anything
 * else: a host that is not the tenant's, or not yet verified, is a 422.
 */
export function HostsField({
  control,
  errors,
  isSubmitting,
  orgSlug,
  setValue,
  tenantSlug,
}: HostsFieldProps) {
  const t = useTranslations('dashboard.routes.fields.hosts');
  const validationText = useValidationText();
  const [search, setSearch] = useState('');
  const scope = useWatch({ control, name: 'hostScope' });
  const hosts = useWatch({ control, name: 'hosts' }) ?? [];

  const {
    data: domainList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantDomains(orgSlug ?? '', tenantSlug ?? '', { limit: 100 }),
    queryKey: ['tenant-domains', orgSlug, tenantSlug, 'route-hosts'],
  });

  const domains = (domainList?.items ?? []).filter(
    (domain) => domain.verificationStatus === 'Verified',
  );
  const matches = domains.filter((domain) =>
    domain.domain.toLowerCase().includes(search.trim().toLowerCase()),
  );

  function choose(next: 'All' | 'Specific') {
    setValue('hostScope', next, { shouldDirty: true, shouldValidate: true });

    if (next === 'All') {
      setValue('hosts', [], { shouldDirty: true, shouldValidate: true });
    }
  }

  function toggle(domain: string) {
    const next = hosts.includes(domain)
      ? hosts.filter((host) => host !== domain)
      : [...hosts, domain];

    setValue('hosts', next, { shouldDirty: true, shouldValidate: true });
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <span className="text-xs font-semibold text-white">{t('title')}</span>
        <span className="text-xs text-textGray">{t('description')}</span>
      </div>

      <div className="flex gap-2">
        <button
          type="button"
          disabled={isSubmitting}
          onClick={() => choose('All')}
          className={cn(
            choiceClassName,
            scope === 'All'
              ? 'border-transparent bg-primary/15 text-primary'
              : 'border-borderGray bg-cardBg text-textGray hover:border-white/20 hover:text-white',
          )}
        >
          {t('all')}
        </button>
        <button
          type="button"
          disabled={isSubmitting}
          onClick={() => choose('Specific')}
          className={cn(
            choiceClassName,
            scope === 'Specific'
              ? 'border-transparent bg-primary/15 text-primary'
              : 'border-borderGray bg-cardBg text-textGray hover:border-white/20 hover:text-white',
          )}
        >
          {t('specific')}
        </button>
      </div>

      {scope === 'All' ? (
        <p className="text-xs text-textGray">{t('allHint')}</p>
      ) : (
        <>
          <Input
            label={t('search')}
            placeholder="acme.com"
            containerClassName="mb-0"
            className="bg-cardBg"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            disabled={isSubmitting}
          />

          {isLoading ? (
            <p className="text-xs text-textGray">{t('loading')}</p>
          ) : error ? (
            <p className="text-xs text-error">{getApiErrorMessage(error, t('loadFailed'))}</p>
          ) : domains.length === 0 ? (
            <p className="text-xs text-textGray">{t('none')}</p>
          ) : (
            <div className="max-h-48 overflow-y-auto rounded-lg border border-borderGray">
              {matches.length === 0 ? (
                <p className="px-3 py-2.5 text-xs text-textGray">{t('noMatch', { search })}</p>
              ) : (
                matches.map((domain, index) => {
                  const isSelected = hosts.includes(domain.domain);
                  const isVerified = domain.verificationStatus === 'Verified';

                  return (
                    <button
                      key={domain.id}
                      type="button"
                      disabled={isSubmitting}
                      onClick={() => toggle(domain.domain)}
                      className={cn(
                        'flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left transition',
                        index > 0 && 'border-t border-borderGray',
                        isSelected ? 'bg-focus/10' : 'hover:bg-hoverBg',
                      )}
                    >
                      <span
                        className={cn(
                          'text-xs font-medium',
                          isSelected ? 'text-focus' : 'text-white',
                        )}
                      >
                        {domain.domain}
                      </span>
                      <span className="flex items-center gap-2">
                        {isVerified ? null : (
                          <span className="text-[10px] font-semibold text-orange">
                            {t('notVerified')}
                          </span>
                        )}
                        {isSelected ? (
                          <span className="material-symbols-rounded text-base! text-focus">
                            check
                          </span>
                        ) : null}
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          )}

          {errors.hosts ? (
            <p className="text-xs text-error">{validationText(errors.hosts.message)}</p>
          ) : (
            <p className="text-xs text-textGray">{t('selected', { count: hosts.length })}</p>
          )}
        </>
      )}
    </div>
  );
}
