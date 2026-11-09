'use client';

import { useState } from 'react';
import Image from 'next/image';
import { useTranslations } from 'next-intl';
import dotPattern from '@/assets/dotpattern.png';
import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { useQuery } from '@tanstack/react-query';
import { ActivityCalendarCard } from '@/components/dashboard/overview/activity-calendar-card';
import { ChangeBadge } from '@/components/dashboard/overview/change-badge';
import { MetricCard } from '@/components/dashboard/overview/metric-card';
import { MiniLineChart } from '@/components/dashboard/overview/mini-line-chart';
import { OverviewSummaryCard } from '@/components/dashboard/overview/overview-summary-card';
import { ProgressRing } from '@/components/dashboard/overview/progress-ring';
import { RecentActivityCard } from '@/components/dashboard/overview/recent-activity-card';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useMetricsWindow } from '@/hooks/overview/use-metrics-window';
import { useOrgActivity } from '@/hooks/overview/use-org-activity';
import { useOrgMetrics } from '@/hooks/overview/use-org-metrics';
import { deriveErrorMessage, getApiErrorMessage, getAuditLog } from '@/lib/api';
import {
  formatLastLoginDate,
  formatLatency,
  formatNumber,
  formatPercent,
  formatTrend,
  getFailedAttemptsTone,
  hasSuccessRateSeriesData,
  getSuccessRatePoints,
  getTrendTone,
  getWindowButtonClass,
  toMetricItem,
} from '@/lib/overview/metrics';
import { useAuthStore } from '@/store/auth-store';
import type { OverviewMetricItem } from '@/types/overview';

export default function OverviewPage() {
  const t = useTranslations('dashboard.overview');
  const tErrors = useTranslations('common.errors');
  const currentUserEmail = useAuthStore((state) => state.user?.email);
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const { canViewAuditLog } = useOrgAccess();
  const { handleMetricsWindowChange, metricsWindow } = useMetricsWindow();
  const { data: metrics, error, isLoading } = useOrgMetrics(organizationSlug, metricsWindow);
  const {
    data: activity,
    error: activityError,
    isLoading: isActivityLoading,
  } = useOrgActivity(organizationSlug, canViewAuditLog);
  const [selectedActivityCategory, setSelectedActivityCategory] = useState<string | null>(null);
  const activityCategory = selectedActivityCategory ?? activity?.categories[0] ?? '';
  const {
    data: recentActivityLog,
    error: recentActivityError,
    isLoading: isRecentActivityLoading,
  } = useQuery({
    enabled: Boolean(organizationSlug) && canViewAuditLog,
    queryFn: () =>
      getAuditLog(organizationSlug ?? '', {
        limit: 3,
        sortDirection: 'desc',
        sortField: 'occurred_at',
      }),
    queryKey: ['recent-activity', organizationSlug],
  });

  const averageAuthTime = formatLatency(metrics?.authentication.averageAuthTime.currentMs);
  const authSuccessRate = formatPercent(metrics?.authentication.successRate.current);
  const failedAttempts = metrics?.authentication.failedAttempts.failed;
  const failedAttemptsPercent = metrics?.authentication.failedAttempts.percent;
  const totalAttempts = metrics?.authentication.failedAttempts.total;
  const failedAttemptsValue = failedAttempts ?? 0;
  const totalAttemptsValue = totalAttempts ?? 0;
  const hasAuthSuccessRateData = hasSuccessRateSeriesData(metrics);
  const lastLoginDate = formatLastLoginDate(metrics?.authentication.lastLogin);
  const usersMetrics: OverviewMetricItem[] = [
    toMetricItem(
      t('metrics.totalUsers'),
      formatNumber(metrics?.users.current),
      metrics?.users.trend ?? {},
    ),
    toMetricItem(
      t('metrics.totalTenants'),
      formatNumber(metrics?.tenants.current),
      metrics?.tenants.trend ?? {},
    ),
    toMetricItem(
      t('metrics.activeSessions'),
      formatNumber(metrics?.activeSessions.current),
      metrics?.activeSessions.trend ?? {},
    ),
  ];
  const apiMetrics: OverviewMetricItem[] = [
    toMetricItem(
      t('metrics.apiRequests'),
      formatNumber(metrics?.api.requestCount.current),
      metrics?.api.requestCount.trend ?? {},
    ),
    toMetricItem(
      t('metrics.errorRate'),
      formatPercent(metrics?.api.errorRate.current),
      metrics?.api.errorRate.trend ?? {},
    ),
    toMetricItem(
      t('metrics.p95Latency'),
      formatLatency(metrics?.api.p95Latency.currentMs),
      metrics?.api.p95Latency.trend ?? {},
    ),
  ];
  const errorMessage = deriveErrorMessage(
    [!organizationSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const activityErrorMessage = deriveErrorMessage(
    [activityError, getApiErrorMessage(activityError, t('activityLoadFailed'))],
    [recentActivityError, getApiErrorMessage(recentActivityError, t('activityLoadFailed'))],
  );

  return (
    <div className="h-full overflow-y-auto">
      <DashboardPageHeader icon="dashboard" title={t('title')} />

      <div className="mx-auto w-full max-w-360 space-y-4 px-4 py-4">
        {errorMessage ? (
          <div className="rounded-lg border border-error bg-cardBg px-4 py-3 text-sm text-error">
            {errorMessage}
          </div>
        ) : null}

        <div className="overview-summary-grid">
          <OverviewSummaryCard title={t('authTime.title')} className="overview-auth-time-card">
            <div className="auth-time-compact mt-4 flex h-13.25 items-center justify-between gap-3 rounded-[10px] border border-borderGray bg-linear-to-r from-surfaceMuted to-cardBg px-4 py-2.5">
              <div className="flex items-center gap-4">
                <div className="flex items-center">
                  <div className="flex size-8 items-center justify-center text-primary">
                    <svg viewBox="0 0 24 24" className="size-5" fill="none" aria-hidden="true">
                      <path
                        d="M9 2h6M12 7v5l3 2M19.5 12.5a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0Z"
                        stroke="currentColor"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="1.8"
                      />
                    </svg>
                  </div>
                  <p className="text-2xl font-semibold tracking-normal text-white">
                    {isLoading ? '...' : averageAuthTime}
                  </p>
                </div>
                <Image src={dotPattern} alt="" className="object-contain" />
              </div>
              <div className="flex h-8 items-center rounded-full bg-surfaceRaised text-sm font-medium text-white">
                <p className="px-3 py-1">{t('authTime.lastLogin')}</p>
                <p className="h-full rounded-full bg-surfaceSuccess px-3 py-1">{lastLoginDate}</p>
              </div>
            </div>

            <div className="auth-time-range mt-3 h-15 items-center justify-between gap-2 rounded-[14px] border border-borderGray bg-linear-to-r from-surfaceMuted to-cardBg px-4 py-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="flex size-6 items-center justify-center text-primary">
                    <svg viewBox="0 0 24 24" className="size-5.5" fill="none" aria-hidden="true">
                      <path
                        d="M9 2h6M12 7v5l3 2M19.5 12.5a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0Z"
                        stroke="currentColor"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="1.8"
                      />
                    </svg>
                  </span>
                  <p className="text-[28px] font-semibold leading-none tracking-normal text-white">
                    {isLoading ? '...' : averageAuthTime}
                  </p>
                </div>
                <p className="mt-1 truncate text-xs font-normal leading-tight tracking-normal text-white">
                  <span className="text-textGray">{t('authTime.lastLoginColon')}</span>{' '}
                  {lastLoginDate}
                </p>
              </div>
              <Image src={dotPattern} alt="" className="w-17 shrink-0 object-contain" />
            </div>
          </OverviewSummaryCard>

          <OverviewSummaryCard title={t('successRate.title')} titleClassName="text-center">
            {isLoading || hasAuthSuccessRateData ? (
              <div className="mt-4 flex h-10 items-center justify-center gap-4">
                <MiniLineChart points={getSuccessRatePoints(metrics)} className="w-25 shrink-0" />
                <div className="flex min-w-0 shrink-0 items-end gap-1">
                  <div className="flex flex-col items-start gap-0.5">
                    <p className="text-xl font-bold tracking-normal text-white">
                      {isLoading ? '...' : authSuccessRate}
                    </p>
                    <p className="text-[10px] font-medium text-textGray">
                      {t('successRate.comparison')}
                    </p>
                  </div>
                  <ChangeBadge
                    value={formatTrend(metrics?.authentication.successRate.trend.changePct)}
                    tone={getTrendTone(
                      metrics?.authentication.successRate.trend.direction,
                      metrics?.authentication.successRate.trend.changePct,
                    )}
                  />
                </div>
              </div>
            ) : (
              <div className="mt-4 flex h-10 items-center justify-center">
                <p className="text-xl font-bold tracking-normal text-white">{t('notAvailable')}</p>
              </div>
            )}
          </OverviewSummaryCard>

          <OverviewSummaryCard title={t('failedLogins.title')} titleClassName="text-center">
            <div className="mt-4 flex items-center justify-center gap-4">
              <ProgressRing value={failedAttemptsValue} max={totalAttemptsValue || 1} />
              <div className="flex flex-col min-w-0 items-start gap-0.5">
                <div>
                  <p className="text-2xl tracking-normal">
                    <span className="font-bold text-primary">
                      {isLoading ? '...' : formatNumber(failedAttempts)}
                    </span>
                    <span className="font-normal text-textGray">
                      {' '}
                      / {formatNumber(totalAttempts)}
                    </span>
                  </p>
                </div>
                <div className="flex items-center gap-1.75">
                  <p className="text-[10px] font-medium text-textGray">
                    {t('failedLogins.ofTotal')}
                  </p>
                  <ChangeBadge
                    value={formatPercent(failedAttemptsPercent)}
                    tone={getFailedAttemptsTone(failedAttemptsPercent)}
                  />
                </div>
              </div>
            </div>
          </OverviewSummaryCard>
        </div>

        <section className="rounded-lg border border-borderGray bg-cardBg pt-2.75 px-4 pb-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-base font-semibold text-white">{t('metrics.title')}</h2>
            <div className="flex w-full rounded-lg bg-surfaceRaised p-1 sm:w-auto">
              <button
                type="button"
                className={getWindowButtonClass(metricsWindow === 'daily')}
                onClick={() => handleMetricsWindowChange('daily')}
              >
                {t('metrics.daily')}
              </button>
              <button
                type="button"
                className={getWindowButtonClass(metricsWindow === 'monthly')}
                onClick={() => handleMetricsWindowChange('monthly')}
              >
                {t('metrics.monthly')}
              </button>
            </div>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <MetricCard title={t('metrics.users')} items={usersMetrics} />
            <MetricCard title={t('metrics.apiUsage')} items={apiMetrics} />
          </div>
        </section>

        {activityErrorMessage ? (
          <div className="rounded-lg border border-error bg-cardBg px-4 py-3 text-sm text-error">
            {activityErrorMessage}
          </div>
        ) : null}

        {canViewAuditLog ? (
          <div className="grid gap-4 lg:grid-cols-2">
            <ActivityCalendarCard
              categories={activity?.categories ?? []}
              days={activity?.days ?? []}
              isLoading={isActivityLoading}
              selectedCategory={activityCategory}
              onCategoryChange={setSelectedActivityCategory}
            />
            <RecentActivityCard
              currentUserEmail={currentUserEmail}
              entries={recentActivityLog?.items ?? []}
              isLoading={isRecentActivityLoading}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}
