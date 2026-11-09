'use client';

import { useEffect, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { FloatingTooltip } from '@/components/ui/floating-tooltip';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getNotificationsCount, getTenantNotificationsCount } from '@/lib/api';
import {
  invalidateNotificationListQueries,
  invalidateTenantNotificationListQueries,
  notificationCountQueryKey,
  tenantNotificationCountQueryKey,
} from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';
import { cn } from '@/utils/cn';

type SidebarNotificationsProps = {
  href?: string;
  isCollapsed?: boolean;
};

export function SidebarNotifications({
  href = '/notifications',
  isCollapsed = false,
}: SidebarNotificationsProps) {
  const t = useTranslations('dashboard.sidebar');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const pathname = usePathname();
  const previousCountRef = useRef<number | null>(null);
  const sessionOrganizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const { isTenantView, orgSlug: tenantRouteOrgSlug, tenantSlug } = useTenantRouteParams();
  const organizationSlug = isTenantView ? tenantRouteOrgSlug : sessionOrganizationSlug;
  const isScopeReady = isTenantView
    ? Boolean(organizationSlug && tenantSlug)
    : Boolean(organizationSlug);
  const { data: count = 0 } = useQuery({
    enabled: isScopeReady,
    queryFn: () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (isTenantView) {
        if (!tenantSlug) {
          throw new Error(tErrors('tenantMissing'));
        }

        return getTenantNotificationsCount(organizationSlug, tenantSlug);
      }

      return getNotificationsCount(organizationSlug);
    },
    queryKey: isTenantView
      ? tenantNotificationCountQueryKey(organizationSlug, tenantSlug)
      : notificationCountQueryKey(organizationSlug),
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });

  useEffect(() => {
    if (!isScopeReady) {
      previousCountRef.current = null;
      return;
    }

    const previousCount = previousCountRef.current;
    previousCountRef.current = count;

    if (previousCount !== null && count > previousCount) {
      if (isTenantView) {
        void invalidateTenantNotificationListQueries(queryClient, organizationSlug, tenantSlug);
        return;
      }

      void invalidateNotificationListQueries(queryClient, organizationSlug);
    }
  }, [count, isScopeReady, isTenantView, organizationSlug, queryClient, tenantSlug]);

  const isActive = pathname === href;
  const hasNotifications = count > 0;
  const displayCount = count > 99 ? '99+' : String(count);

  return (
    <section>
      <Link
        href={href}
        className={cn(
          'group relative flex h-8 items-center gap-3 rounded-md px-2 py-1.5 text-xs font-medium text-textGray transition',
          isCollapsed && 'justify-center px-0',
          !isCollapsed && 'justify-between',
          isActive && 'border border-borderGray text-white bg-cardBg',
          isActive && isCollapsed && 'text-white',
          !isActive && 'hover:border-transparent hover:text-white',
        )}
      >
        {isActive ? (
          <span
            aria-hidden="true"
            className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary"
          />
        ) : null}
        <span className="flex min-w-0 items-center gap-3">
          <span
            className={cn(
              'relative flex h-6 w-6 shrink-0 items-center justify-center text-textGray transition',
              isActive && 'text-primary',
              !isActive && 'hover:border-transparent group-hover:text-white',
            )}
          >
            <FloatingTooltip content={t('notifications')} disabled={!isCollapsed} placement="right">
              <span className="material-symbols-rounded" aria-hidden="true">
                notifications
              </span>
            </FloatingTooltip>
            {isCollapsed && hasNotifications ? (
              <span
                aria-label={t('unreadNotifications', { count: displayCount })}
                className="absolute right-0 top-0 h-3 w-3 rounded-full border-2 border-appBg bg-focus"
              />
            ) : null}
          </span>
          {!isCollapsed && <span className="truncate">{t('notifications')}</span>}
        </span>

        {!isCollapsed && hasNotifications ? (
          <span
            aria-label={t('unreadNotifications', { count: displayCount })}
            className="flex h-4.5 min-w-4.5 items-center justify-center rounded-full bg-focus px-1.5 py-0.5 text-[10px] font-bold leading-none text-white"
          >
            {displayCount}
          </span>
        ) : null}
      </Link>
    </section>
  );
}
