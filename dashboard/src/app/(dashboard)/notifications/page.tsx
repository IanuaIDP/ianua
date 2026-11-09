'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  type InfiniteData,
  type QueryKey,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { useLocale, useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { Tooltip } from '@/components/ui/tooltip';
import { NOTIFICATIONS_PAGE_SIZE } from '@/constants/notification';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  getApiErrorMessage,
  getNotifications,
  getNotificationsCount,
  getTenantNotifications,
  getTenantNotificationsCount,
  markAllNotificationsAsRead,
  markAllTenantNotificationsAsRead,
  markNotificationAsRead,
  markTenantNotificationAsRead,
} from '@/lib/api';
import type { NotificationList } from '@/lib/api';
import {
  invalidateNotificationQueries,
  invalidateTenantNotificationQueries,
  notificationCountQueryKey,
  notificationListQueryKey,
  tenantNotificationCountQueryKey,
  tenantNotificationListQueryKey,
} from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';
import { cn } from '@/utils/cn';
import { formatRelativeTime, parseBackendTimestamp } from '@/utils/date';

type NotificationTab = 'all' | 'unread';

const tabs: NotificationTab[] = ['all', 'unread'];

export default function NotificationsPage() {
  const t = useTranslations('dashboard.notifications');
  const { showNotification } = useNotification();
  const locale = useLocale();
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const loadMoreRef = useRef<HTMLDivElement>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<NotificationTab>('all');
  const sessionOrganizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const { isTenantView, orgSlug: tenantRouteOrgSlug, tenantSlug } = useTenantRouteParams();
  const organizationSlug = isTenantView ? tenantRouteOrgSlug : sessionOrganizationSlug;
  const isScopeReady = isTenantView
    ? Boolean(organizationSlug && tenantSlug)
    : Boolean(organizationSlug);
  const unreadOnly = activeTab === 'unread';
  const {
    data: notificationPages,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading,
  } = useInfiniteQuery<
    NotificationList,
    Error,
    InfiniteData<NotificationList>,
    QueryKey,
    string | undefined
  >({
    enabled: isScopeReady,
    initialPageParam: undefined,
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    queryFn: ({ pageParam }) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (isTenantView) {
        if (!tenantSlug) {
          throw new Error(tErrors('tenantMissing'));
        }

        return getTenantNotifications(organizationSlug, tenantSlug, {
          after: pageParam,
          limit: NOTIFICATIONS_PAGE_SIZE,
          unreadOnly,
        });
      }

      return getNotifications(organizationSlug, {
        after: pageParam,
        limit: NOTIFICATIONS_PAGE_SIZE,
        unreadOnly,
      });
    },
    queryKey: isTenantView
      ? tenantNotificationListQueryKey(organizationSlug, tenantSlug, activeTab)
      : notificationListQueryKey(organizationSlug, activeTab),
  });
  const notifications = useMemo(
    () => notificationPages?.pages.flatMap((page) => page.items) ?? [],
    [notificationPages],
  );
  const { data: unreadCount = 0 } = useQuery({
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
  });
  const markAsReadMutation = useMutation({
    mutationFn: (notificationId: string) => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (isTenantView) {
        if (!tenantSlug) {
          throw new Error(tErrors('tenantMissing'));
        }

        return markTenantNotificationAsRead(organizationSlug, tenantSlug, notificationId);
      }

      return markNotificationAsRead(organizationSlug, notificationId);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('markReadFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      if (isTenantView) {
        await invalidateTenantNotificationQueries(queryClient, organizationSlug, tenantSlug);
        return;
      }

      await invalidateNotificationQueries(queryClient, organizationSlug);
    },
  });
  const markAllAsReadMutation = useMutation({
    mutationFn: () => {
      if (!organizationSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      if (isTenantView) {
        if (!tenantSlug) {
          throw new Error(tErrors('tenantMissing'));
        }

        return markAllTenantNotificationsAsRead(organizationSlug, tenantSlug);
      }

      return markAllNotificationsAsRead(organizationSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('markReadFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      if (isTenantView) {
        await invalidateTenantNotificationQueries(queryClient, organizationSlug, tenantSlug);
        return;
      }

      await invalidateNotificationQueries(queryClient, organizationSlug);
    },
  });
  const errorMessage = deriveErrorMessage(
    [!isScopeReady, isTenantView ? tErrors('tenantMissing') : tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  useEffect(() => {
    const loadMoreElement = loadMoreRef.current;
    const scrollContainer = scrollContainerRef.current;

    if (!loadMoreElement || !scrollContainer || !hasNextPage) {
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !isFetchingNextPage) {
          void fetchNextPage();
        }
      },
      {
        root: scrollContainer,
        rootMargin: '120px',
      },
    );

    observer.observe(loadMoreElement);

    return () => {
      observer.disconnect();
    };
  }, [fetchNextPage, hasNextPage, isFetchingNextPage, notifications.length]);

  function getTimeAgo(createdAt: string) {
    const date = parseBackendTimestamp(createdAt);

    return date ? formatRelativeTime(date, locale) : '';
  }

  function handleNotificationClick(notificationId: string, isRead: boolean) {
    if (isRead || markAsReadMutation.isPending) {
      return;
    }

    markAsReadMutation.mutate(notificationId);
  }

  function handleMarkAllAsRead() {
    if (!unreadCount || markAllAsReadMutation.isPending) {
      return;
    }

    markAllAsReadMutation.mutate();
  }

  return (
    <div>
      <DashboardPageHeader icon="notifications" title={t('title')} />

      <section className="mx-auto my-4 flex max-h-[calc(100vh-5.25rem)] w-[calc(100%-2rem)] max-w-360 flex-col overflow-hidden rounded-lg border border-borderGray bg-cardBg">
        <div className="flex flex-col gap-4 px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="text-base font-bold text-white">{t('title')}</h2>
            <p className="mt-2 text-xs font-medium text-textGray">
              {isTenantView ? t('descriptionTenant') : t('descriptionOrganization')}
            </p>
          </div>

          {unreadCount ? (
            <Button
              type="button"
              variant="outline"
              onClick={handleMarkAllAsRead}
              disabled={markAllAsReadMutation.isPending}
              className="h-8 w-auto shrink-0 border-borderGray bg-cardBg px-4 py-[6.5px] text-sm font-medium tracking-normal text-white hover:bg-hoverBg"
            >
              {t('markAllAsRead', { count: unreadCount })}
            </Button>
          ) : null}
        </div>

        <div className="border-b border-borderGray px-4">
          <div className="flex h-9 items-end gap-5">
            {tabs.map((tab) => {
              const isActive = activeTab === tab;

              return (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={cn(
                    'relative h-full text-xs font-semibold transition',
                    isActive ? 'text-primary' : 'text-textGray hover:text-white',
                  )}
                >
                  {t(`tabs.${tab}`)}
                  {isActive ? (
                    <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-primary" />
                  ) : null}
                </button>
              );
            })}
          </div>
        </div>

        {errorMessage ? (
          <p className="px-4 py-6 text-sm font-medium text-error">{errorMessage}</p>
        ) : null}

        {!errorMessage ? (
          <div ref={scrollContainerRef} className="min-h-0 flex-1 overflow-auto px-4 pt-4">
            <div className="flex flex-col gap-2">
              {isLoading ? (
                <p className="py-10 text-center text-xs font-medium text-textGray">
                  {t('loading')}
                </p>
              ) : notifications.length ? (
                <>
                  {notifications.map((notification) => (
                    <button
                      key={notification.id}
                      type="button"
                      onClick={() => handleNotificationClick(notification.id, notification.isRead)}
                      className={cn(
                        'group/notification relative flex min-h-13 w-full items-start justify-between gap-4 rounded-lg border px-4 py-3 text-left transition',
                        notification.isRead
                          ? 'border-borderGray bg-cardBg'
                          : 'cursor-pointer border-focus/20 bg-focus/5 hover:bg-focus/10',
                      )}
                    >
                      {!notification.isRead ? (
                        <span
                          aria-hidden="true"
                          className="absolute left-0 top-1/2 h-8 w-0.5 -translate-y-1/2 rounded-r-full bg-focus shadow-focus-line-glow"
                        />
                      ) : null}
                      <div className="min-w-0">
                        <h3 className="break-words text-xs font-bold text-white">
                          {notification.title}
                        </h3>
                        <p className="mt-1 break-words text-xs font-medium text-textGray">
                          {notification.body}
                        </p>
                      </div>

                      <div className="flex shrink-0 flex-col items-end gap-4">
                        {!notification.isRead ? (
                          <Tooltip content={t('markAsRead')} side="bottom-left">
                            <span
                              aria-label={t('unread')}
                              className="relative flex size-2 items-center justify-center text-textGray"
                            >
                              <span className="size-2 rounded-full bg-focus transition group-hover/notification:scale-0 group-hover/notification:opacity-0 group-focus-visible/notification:scale-0 group-focus-visible/notification:opacity-0" />
                              <span
                                aria-hidden="true"
                                className="material-symbols-rounded absolute text-[17px] leading-none opacity-0 transition group-hover/notification:opacity-100 group-focus-visible/notification:opacity-100"
                              >
                                done_all
                              </span>
                            </span>
                          </Tooltip>
                        ) : null}
                        <span className="text-xs font-medium text-textGray">
                          {getTimeAgo(notification.createdAt)}
                        </span>
                      </div>
                    </button>
                  ))}
                  <div
                    ref={loadMoreRef}
                    className="flex justify-center px-4 py-3 text-center text-xs font-medium text-textGray"
                  >
                    {hasNextPage
                      ? isFetchingNextPage
                        ? t('loadingMore')
                        : t('scrollForMore')
                      : t('noMore')}
                  </div>
                </>
              ) : (
                <p className="py-10 text-center text-xs font-medium text-textGray">
                  <span className="inline-flex items-center gap-2">
                    <span className="material-symbols-rounded">feedback</span>
                    {t('empty')}
                  </span>
                </p>
              )}
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
