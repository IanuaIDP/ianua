'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';
import { useWatch, type Control, type FieldErrors, type UseFormSetValue } from 'react-hook-form';

import { useFieldError } from '@/hooks/i18n/use-field-error';
import { getApiErrorMessage, getTenantDomains } from '@/lib/api';
import type { AddConnectionInput } from '@/schemas/connection-schemas';
import { cn } from '@/utils/cn';

type AllowedDomainsFieldProps = {
  control: Control<AddConnectionInput>;
  errors: FieldErrors<AddConnectionInput>;
  isSubmitting: boolean;
  orgSlug?: string;
  setValue: UseFormSetValue<AddConnectionInput>;
  tenantSlug?: string;
};

/**
 * Picks the email domains a connection's identity provider may sign people in
 * for.
 *
 * A provider is trusted only for these: it cannot sign in an account at any
 * other address, so a test provider cannot claim to be an administrator
 * elsewhere. Options are the tenant's verified domains because the API
 * rejects anything else, and binding one needs `Federation(Manage)`.
 */
export function AllowedDomainsField({
  control,
  errors,
  isSubmitting,
  orgSlug,
  setValue,
  tenantSlug,
}: AllowedDomainsFieldProps) {
  const t = useTranslations('dashboard.connections.allowedDomains');
  const allowedDomainsError = useFieldError(errors.allowedDomains?.message);
  const selected = useWatch({ control, name: 'allowedDomains' }) ?? [];

  const {
    data: domainList,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantDomains(orgSlug ?? '', tenantSlug ?? '', { limit: 100 }),
    queryKey: ['tenant-domains', orgSlug, tenantSlug, 'connection-domains'],
  });

  const domains = (domainList?.items ?? []).filter(
    (domain) => domain.verificationStatus === 'Verified',
  );

  function toggle(domain: string) {
    const next = selected.includes(domain)
      ? selected.filter((chosen) => chosen !== domain)
      : [...selected, domain];

    setValue('allowedDomains', next, { shouldDirty: true, shouldValidate: true });
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
      ) : domains.length === 0 ? (
        <p className="text-xs text-textGray">{t('none')}</p>
      ) : (
        <div className="max-h-48 overflow-y-auto rounded-lg border border-borderGray">
          {domains.map((domain, index) => {
            const isSelected = selected.includes(domain.domain);

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
                  className={cn('text-xs font-medium', isSelected ? 'text-focus' : 'text-white')}
                >
                  {domain.domain}
                </span>
                {isSelected ? (
                  <span className="material-symbols-rounded text-base! text-focus">check</span>
                ) : null}
              </button>
            );
          })}
        </div>
      )}

      {allowedDomainsError ? <p className="text-xs text-error">{allowedDomainsError}</p> : null}
    </div>
  );
}
