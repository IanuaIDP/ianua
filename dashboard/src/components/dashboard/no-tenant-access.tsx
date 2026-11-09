'use client';

import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { getApiErrorMessage, switchOrganizationTenant } from '@/lib/api';
import { useAuthStore } from '@/store/auth-store';
import type { AccessTenant } from '@/types/auth';

type NoTenantAccessProps = {
  description: string;
};

/**
 * What a member sees on a tenant they hold no grant on: the tenants they do
 * reach, each opened by moving their session there.
 */
export function NoTenantAccess({ description }: NoTenantAccessProps) {
  const t = useTranslations('dashboard.layout');
  const router = useRouter();
  const { showNotification } = useNotification();
  const { refresh, tenants } = useOrgAccess();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const setTokens = useAuthStore((state) => state.setTokens);
  const updateUser = useAuthStore((state) => state.updateUser);
  const { isPending: isChecking, mutate: checkAgain } = useMutation({
    mutationFn: refresh,
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('noTenantRefreshFailed')),
        type: 'error',
      });
    },
  });
  const { isPending: isOpening, mutate: openTenant } = useMutation({
    mutationFn: (tenant: AccessTenant) =>
      switchOrganizationTenant(organizationSlug ?? '', tenant.tenantId),
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('noTenantOpenFailed')),
        type: 'error',
      });
    },
    onSuccess: ({ accessToken, sessionId, tenantId }, tenant) => {
      setTokens({ accessToken });
      updateUser({
        id: sessionId,
        tenantId,
        tenantName: tenant.displayName,
        tenantSlug: tenant.slug,
      });
      router.push(`/tenants/${encodeURIComponent(tenant.slug)}`);
    },
  });

  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center">
      <span className="material-symbols-rounded text-4xl text-textGray" aria-hidden="true">
        lock
      </span>
      <div>
        <h1 className="text-lg font-semibold text-white">{t('noTenantAccessTitle')}</h1>
        <p className="max-w-sm text-sm text-textGray">{description}</p>
      </div>

      {tenants.length > 0 ? (
        <div className="flex w-full max-w-sm flex-col gap-2">
          <p className="text-xs font-medium text-textGray">{t('noTenantOpenOther')}</p>
          {tenants.map((tenant) => (
            <button
              key={tenant.tenantId}
              type="button"
              disabled={isOpening}
              onClick={() => openTenant(tenant)}
              className="flex w-full items-center justify-between gap-3 rounded-lg border border-borderGray px-3 py-2 text-left text-sm font-medium text-white transition hover:bg-hoverBg disabled:pointer-events-none disabled:opacity-50"
            >
              <span className="min-w-0 flex-1 truncate">{tenant.displayName}</span>
              <span className="material-symbols-rounded shrink-0 text-textGray" aria-hidden="true">
                arrow_forward
              </span>
            </button>
          ))}
        </div>
      ) : null}

      <Button
        type="button"
        variant="outline"
        isLoading={isChecking}
        disabled={isChecking}
        onClick={() => checkAgain()}
        className="h-8 w-auto border-borderGray bg-surfaceChip px-4 py-0 text-xs font-medium text-white hover:bg-hoverBg"
      >
        {t('noTenantCheckAgain')}
      </Button>
    </div>
  );
}
