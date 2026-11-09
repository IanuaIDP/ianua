'use client';

import { useQuery } from '@tanstack/react-query';
import Image from 'next/image';
import { useTranslations } from 'next-intl';

import dotPattern from '@/assets/dotpattern.png';
import { ChangeBadge } from '@/components/dashboard/overview/change-badge';
import { MetricCard } from '@/components/dashboard/overview/metric-card';
import { MiniLineChart } from '@/components/dashboard/overview/mini-line-chart';
import { OverviewSummaryCard } from '@/components/dashboard/overview/overview-summary-card';
import { ProgressRing } from '@/components/dashboard/overview/progress-ring';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { useMetricsWindow } from '@/hooks/overview/use-metrics-window';
import { useTenantMetrics } from '@/hooks/tenants/use-tenant-metrics';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { deriveErrorMessage, getApiErrorMessage, getTenant } from '@/lib/api';
import {
  formatLastLoginDate,
  formatLatency,
  formatNumber,
  formatPercent,
  formatTrend,
  hasSuccessRateSeriesData,
  getSuccessRatePoints,
  getTrendTone,
  getWindowButtonClass,
  toMetricItem,
} from '@/lib/overview/metrics';
import { useAuthStore } from '@/store/auth-store';
import type { Company, OverviewMetricItem } from '@/types/overview';
import { cn } from '@/utils/cn';
import { formatBackendDate } from '@/utils/date';

export function TenantOverviewSection() {
  const t = useTranslations('dashboard.tenantOverview');
  const tOverview = useTranslations('dashboard.overview');
  const tErrors = useTranslations('common.errors');
  const copy = useCopyToClipboard();
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { canView, hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const canViewMetrics = hasPermission('Metrics', 'View');
  const canViewTenantSettings = canView('TenantSettings');
  const sessionTenantName = useAuthStore((state) => state.user?.tenantName);
  const { handleMetricsWindowChange, metricsWindow } = useMetricsWindow();
  const {
    data: metrics,
    error,
    isLoading,
  } = useTenantMetrics(orgSlug, tenantSlug, metricsWindow, { enabled: canViewMetrics });
  // The tenant record carries the same profile fields as the metrics payload,
  // so users without Metrics permission still see a filled-in card. Reading it
  // needs TenantSettings, checked here for org and tenant sessions alike so
  // both see the same card; without it the card shrinks to name and slug.
  const { data: cachedTenantDetail } = useQuery({
    enabled: Boolean(orgSlug) && !isLoadingPermissions && canViewTenantSettings,
    queryFn: () => getTenant(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-detail', orgSlug, tenantSlug],
    retry: false,
  });
  // Other screens share this query key, so ignore cached data without permission.
  const tenantDetail = canViewTenantSettings ? cachedTenantDetail : undefined;
  const loginUrl = !isTenantView ? tenantDetail?.loginUrl : null;

  async function copyLoginUrl() {
    if (!loginUrl) {
      return;
    }

    await copy(loginUrl, t('loginUrlCopied'));
  }

  const detailCompany: Company | undefined = tenantDetail
    ? {
        contactEmail: tenantDetail.contactEmail,
        displayName: tenantDetail.displayName,
        locale: tenantDetail.locale,
        primaryDomain: tenantDetail.primaryDomain,
        slug: tenantDetail.slug,
        timezone: tenantDetail.timezone,
      }
    : undefined;
  const company: Company | undefined =
    (canViewMetrics ? metrics?.company : undefined) ??
    detailCompany ??
    (canViewMetrics && isLoading
      ? undefined
      : { displayName: sessionTenantName ?? tenantSlug, slug: tenantSlug });
  // `tenantDetail.created` is already formatted; the metrics date is raw.
  const createdLabel = metrics?.company?.createdAt
    ? formatBackendDate(metrics.company.createdAt)
    : (tenantDetail?.created ?? null);
  const hasProfileDetails = Boolean(company?.locale || company?.timezone || createdLabel);

  const companyDisplayName = company?.displayName;
  const averageAuthTime = formatLatency(metrics?.authentication.averageAuthTime.currentMs);
  const failedAttempts = metrics?.authentication.failedAttempts.failed;
  const healthScore = Math.min(Math.max(metrics?.health ?? 0, 0), 100);
  const hasAuthSuccessRateData = hasSuccessRateSeriesData(metrics);
  const lastLoginDate = formatLastLoginDate(metrics?.authentication.lastLogin);
  const successRate = formatPercent(metrics?.authentication.successRate.current);
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [canViewMetrics && error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const usersMetrics: OverviewMetricItem[] = [
    toMetricItem(
      tOverview('metrics.totalUsers'),
      formatNumber(metrics?.users.current),
      metrics?.users.trend ?? {},
    ),
    toMetricItem(
      t('activeUsers'),
      formatNumber(metrics?.activeUsers.current),
      metrics?.activeUsers.trend ?? {},
    ),
    toMetricItem(
      tOverview('metrics.activeSessions'),
      formatNumber(metrics?.activeSessions.current),
      metrics?.activeSessions.trend ?? {},
    ),
  ];
  const apiMetrics: OverviewMetricItem[] = [
    toMetricItem(
      tOverview('metrics.apiRequests'),
      formatNumber(metrics?.api.requestCount.current),
      metrics?.api.requestCount.trend ?? {},
    ),
    toMetricItem(
      tOverview('successRate.title'),
      successRate,
      metrics?.authentication.successRate.trend ?? {},
    ),
    toMetricItem(
      tOverview('failedLogins.title'),
      formatNumber(failedAttempts),
      metrics?.authentication.failedAttempts.trend ?? {},
    ),
  ];

  return (
    <div className="mx-auto w-full max-w-360 space-y-4">
      {errorMessage ? (
        <div className="rounded-lg border border-error bg-cardBg px-4 py-3 text-sm text-error">
          {errorMessage}
        </div>
      ) : null}

      <section
        className={cn(
          'grid items-stretch gap-4',
          hasProfileDetails && 'xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]',
        )}
      >
        <div className="flex h-40 flex-col overflow-hidden rounded-[10px] border border-primary bg-brand-gradient shadow-primary-line-glow">
          <div className="shrink-0 bg-brand-gradient py-2 text-center text-[10px] font-extrabold uppercase tracking-normal text-cardBg">
            {t('title')}
          </div>
          <div className="mx-1 mb-1 min-h-0 flex-1 overflow-hidden rounded-md bg-cardBg">
            <div className="flex h-full flex-col overflow-hidden rounded-md border border-borderGray bg-cardBg">
              <div className="flex h-15.25 shrink-0 items-center justify-between gap-3 border-b border-borderGray px-4 py-2.5">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-focus/40 bg-focus/20 text-focus shadow-focus-compact-glow">
                    <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                      corporate_fare
                    </span>
                  </span>
                  <div className="min-w-0">
                    <h2 className="truncate text-sm font-bold text-white">{companyDisplayName}</h2>
                    <div className="flex items-center gap-1">
                      <p className="truncate text-xs font-semibold text-primary">
                        {company?.primaryDomain ??
                          (company?.contactEmail ? tOverview('notAvailable') : null)}
                      </p>
                      {company?.primaryDomain ? (
                        <a
                          href={`https://${company.primaryDomain}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={t('openTenant')}
                          className="flex size-4 shrink-0 items-center justify-center text-primary transition hover:text-primary/80"
                        >
                          <span className="material-symbols-rounded" aria-hidden="true">
                            open_in_new
                          </span>
                        </a>
                      ) : null}
                    </div>
                  </div>
                </div>
                {loginUrl ? (
                  <button
                    type="button"
                    onClick={(event) => {
                      event.currentTarget.blur();
                      void copyLoginUrl();
                    }}
                    className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-borderGray px-2.5 text-xs font-medium text-white transition hover:border-transparent hover:bg-hoverBg hover:text-white"
                  >
                    <span className="material-symbols-rounded text-sm!" aria-hidden="true">
                      content_copy
                    </span>
                    {t('loginLink')}
                  </button>
                ) : null}
              </div>
              <dl
                className={cn(
                  'grid h-15.25 flex-1 text-xs',
                  company?.contactEmail && 'sm:grid-cols-2',
                )}
              >
                {company?.contactEmail ? (
                  <div className="flex flex-col border-b border-borderGray px-4 py-2.5 sm:border-b-0 sm:border-r">
                    <dt className="text-textGray">{t('contactEmail')}</dt>
                    <dd className="mt-1 truncate font-semibold text-white">
                      {company.contactEmail}
                    </dd>
                  </div>
                ) : null}
                <div className="flex flex-col px-4 py-2.5">
                  <dt className="text-textGray">{t('slug')}</dt>
                  <dd className="mt-1 truncate font-semibold text-white">
                    {company?.slug ?? tenantSlug}
                  </dd>
                </div>
              </dl>
            </div>
          </div>
        </div>

        {hasProfileDetails ? (
          <div className="flex h-full flex-col gap-4">
            <section className="flex h-40 flex-col rounded-xl border border-borderGray bg-cardBg p-3">
              <h2 className="text-base font-bold text-white">{t('details')}</h2>
              <dl className="mt-3 grid flex-1 overflow-hidden rounded-[10px] border border-borderGray text-sm sm:grid-cols-3">
                <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                  <span className="material-symbols-rounded text-primary" aria-hidden="true">
                    globe
                  </span>
                  <dt className="mt-2 text-textGray">{t('locale')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {company?.locale ?? tOverview('notAvailable')}
                  </dd>
                </div>
                <div className="flex flex-col justify-center border-b border-borderGray px-4 py-3 sm:border-b-0 sm:border-r">
                  <span className="material-symbols-rounded text-primary" aria-hidden="true">
                    schedule
                  </span>
                  <dt className="mt-2 text-textGray">{t('timezone')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {company?.timezone ?? tOverview('notAvailable')}
                  </dd>
                </div>
                <div className="flex flex-col justify-center px-4 py-3">
                  <span className="material-symbols-rounded text-primary" aria-hidden="true">
                    calendar_today
                  </span>
                  <dt className="mt-2 text-textGray">{t('created')}</dt>
                  <dd className="mt-1 text-base font-bold text-white">
                    {createdLabel ?? tOverview('notAvailable')}
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        ) : null}
      </section>

      {!canViewMetrics ? (
        <div className="flex items-center gap-3 rounded-lg border border-borderGray bg-cardBg px-4 py-3 text-sm text-textGray">
          <span className="material-symbols-rounded text-textGray" aria-hidden="true">
            monitoring
          </span>
          {t('noMetrics')}
        </div>
      ) : null}

      {canViewMetrics ? (
        <>
          <div className="overview-summary-grid">
            <OverviewSummaryCard
              title={tOverview('authTime.title')}
              className="overview-auth-time-card"
            >
              <div className="auth-time-compact mt-4 flex h-13.25 items-center justify-between gap-3 rounded-[10px] border border-borderGray bg-linear-to-r from-surfaceMuted to-cardBg px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-rounded text-primary" aria-hidden="true">
                    timer
                  </span>
                  <p className="text-2xl font-semibold text-white">
                    {isLoading ? '...' : averageAuthTime}
                  </p>
                </div>
                <div className="flex h-8 items-center rounded-full bg-surfaceRaised text-sm font-medium text-white">
                  <p className="px-3 py-1">{tOverview('authTime.lastLogin')}</p>
                  <p className="h-full rounded-full bg-surfaceSuccess px-3 py-1">{lastLoginDate}</p>
                </div>
              </div>

              <div className="auth-time-range mt-3 h-15 items-center justify-between gap-2 rounded-[14px] border border-borderGray bg-linear-to-r from-surfaceMuted to-cardBg px-4 py-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="material-symbols-rounded text-primary" aria-hidden="true">
                      timer
                    </span>
                    <p className="text-[28px] font-semibold leading-none tracking-normal text-white">
                      {isLoading ? '...' : averageAuthTime}
                    </p>
                  </div>
                  <p className="mt-1 truncate text-xs font-normal leading-tight tracking-normal text-white">
                    <span className="text-textGray">{tOverview('authTime.lastLoginColon')}</span>{' '}
                    {lastLoginDate}
                  </p>
                </div>
                <Image src={dotPattern} alt="" className="w-17 shrink-0 object-contain" />
              </div>
            </OverviewSummaryCard>

            <OverviewSummaryCard title={t('healthScore')} titleClassName="text-center">
              <div className="mt-4 flex items-center justify-center gap-4">
                <ProgressRing value={healthScore} max={100} />
                <div>
                  <p className="text-2xl font-bold text-primary">
                    {isLoading ? '...' : formatNumber(metrics?.health)}
                    <span className="font-normal text-textGray"> / 100</span>
                  </p>
                  <div className="mt-1 flex items-center gap-2">
                    <p className="text-[10px] font-medium text-textGray">
                      {tOverview('successRate.comparison')}
                    </p>
                    <ChangeBadge
                      value={formatTrend(metrics?.users.trend.changePct)}
                      tone={getTrendTone(
                        metrics?.users.trend.direction,
                        metrics?.users.trend.changePct,
                      )}
                    />
                  </div>
                </div>
              </div>
            </OverviewSummaryCard>

            <OverviewSummaryCard
              title={tOverview('successRate.title')}
              titleClassName="text-center"
            >
              {isLoading || hasAuthSuccessRateData ? (
                <div className="mt-4 flex h-10 items-center justify-center gap-4">
                  <MiniLineChart points={getSuccessRatePoints(metrics)} className="w-25 shrink-0" />
                  <div className="flex min-w-0 shrink-0 items-end gap-1">
                    <div className="flex flex-col items-start gap-0.5">
                      <p className="text-xl font-bold tracking-normal text-white">
                        {isLoading ? '...' : successRate}
                      </p>
                      <p className="text-[10px] font-medium text-textGray">
                        {tOverview('successRate.comparison')}
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
                  <p className="text-xl font-bold tracking-normal text-white">
                    {tOverview('notAvailable')}
                  </p>
                </div>
              )}
            </OverviewSummaryCard>
          </div>

          <section className="rounded-lg border border-borderGray bg-cardBg p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-base font-semibold text-white">{tOverview('metrics.title')}</h2>
              <div className="flex w-fit rounded-lg bg-surfaceRaised p-1 text-xs font-bold">
                <button
                  type="button"
                  className={getWindowButtonClass(metricsWindow === 'daily')}
                  onClick={() => handleMetricsWindowChange('daily')}
                >
                  {tOverview('metrics.daily')}
                </button>
                <button
                  type="button"
                  className={getWindowButtonClass(metricsWindow === 'monthly')}
                  onClick={() => handleMetricsWindowChange('monthly')}
                >
                  {tOverview('metrics.monthly')}
                </button>
              </div>
            </div>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <MetricCard title={tOverview('metrics.users')} items={usersMetrics} />
              <MetricCard title={tOverview('metrics.apiUsage')} items={apiMetrics} />
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
