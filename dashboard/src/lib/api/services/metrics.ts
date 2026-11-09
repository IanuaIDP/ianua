import { getList } from '@/lib/api/crud';
import type { Company, OrgMetrics, TenantMetrics, Trend } from '@/types/overview';

type TrendDirectionResponse = 'up' | 'down' | 'flat' | (string & {});

type TrendResponse = {
  change_pct?: number | null;
  direction: TrendDirectionResponse;
};

type CountMetricResponse = {
  current?: number | null;
  trend: TrendResponse;
};

type LatencyMetricResponse = {
  current_ms?: number | null;
  trend: TrendResponse;
};

type RateMetricResponse = {
  current?: number | null;
  trend: TrendResponse;
};

type FailedAttemptsResponse = {
  failed?: number | null;
  percent?: number | null;
  total?: number | null;
  trend?: TrendResponse;
};

type SuccessRatePointResponse = {
  bucket_start: string;
  failed: number;
  succeeded: number;
  success_rate?: number | null;
};

type AuthenticationMetricsResponse = {
  average_auth_time: LatencyMetricResponse;
  failed_attempts: FailedAttemptsResponse;
  last_login?: string | null;
  success_rate: RateMetricResponse;
  success_rate_series: SuccessRatePointResponse[];
};

type ApiUsageMetricsResponse = {
  error_rate: RateMetricResponse;
  p95_latency: LatencyMetricResponse;
  request_count: CountMetricResponse;
};

type OrgMetricsResponse = {
  active_sessions: CountMetricResponse;
  api: ApiUsageMetricsResponse;
  authentication: AuthenticationMetricsResponse;
  tenants: CountMetricResponse;
  users: CountMetricResponse;
  window: {
    end: string;
    start: string;
  };
};

type CompanyResponse = {
  contact_email?: string | null;
  created_at?: string | null;
  display_name: string;
  locale?: string | null;
  primary_domain?: string | null;
  slug: string;
  timezone?: string | null;
};

type TenantMetricsResponse = {
  active_sessions: CountMetricResponse;
  active_users: CountMetricResponse;
  api: ApiUsageMetricsResponse;
  api_keys: {
    active: boolean;
    active_count?: number | null;
  };
  authentication: AuthenticationMetricsResponse;
  company: CompanyResponse;
  health?: number | null;
  status: string;
  users: CountMetricResponse;
  window: {
    end: string;
    start: string;
  };
};

type GetOrgMetricsParams = {
  since?: string;
  until?: string;
};

function toTrend(response: TrendResponse): Trend {
  return {
    changePct: response.change_pct,
    direction: response.direction,
  };
}

function toCountMetric(response: CountMetricResponse) {
  return {
    current: response.current,
    trend: toTrend(response.trend),
  };
}

function toLatencyMetric(response: LatencyMetricResponse) {
  return {
    currentMs: response.current_ms,
    trend: toTrend(response.trend),
  };
}

function toRateMetric(response: RateMetricResponse) {
  return {
    current: response.current,
    trend: toTrend(response.trend),
  };
}

function toCompany(response: CompanyResponse): Company {
  return {
    contactEmail: response.contact_email,
    createdAt: response.created_at,
    displayName: response.display_name,
    locale: response.locale,
    primaryDomain: response.primary_domain,
    slug: response.slug,
    timezone: response.timezone,
  };
}

function toOrgMetrics(response: OrgMetricsResponse): OrgMetrics {
  return {
    activeSessions: toCountMetric(response.active_sessions),
    api: {
      errorRate: toRateMetric(response.api.error_rate),
      p95Latency: toLatencyMetric(response.api.p95_latency),
      requestCount: toCountMetric(response.api.request_count),
    },
    authentication: {
      averageAuthTime: toLatencyMetric(response.authentication.average_auth_time),
      failedAttempts: {
        failed: response.authentication.failed_attempts.failed,
        percent: response.authentication.failed_attempts.percent,
        total: response.authentication.failed_attempts.total,
        trend: response.authentication.failed_attempts.trend
          ? toTrend(response.authentication.failed_attempts.trend)
          : undefined,
      },
      lastLogin: response.authentication.last_login,
      successRate: toRateMetric(response.authentication.success_rate),
      successRateSeries: response.authentication.success_rate_series.map((point) => ({
        bucketStart: point.bucket_start,
        failed: point.failed,
        succeeded: point.succeeded,
        successRate: point.success_rate,
      })),
    },
    tenants: toCountMetric(response.tenants),
    users: toCountMetric(response.users),
    window: response.window,
  };
}

function toTenantMetrics(response: TenantMetricsResponse): TenantMetrics {
  return {
    activeSessions: toCountMetric(response.active_sessions),
    activeUsers: toCountMetric(response.active_users),
    api: {
      errorRate: toRateMetric(response.api.error_rate),
      p95Latency: toLatencyMetric(response.api.p95_latency),
      requestCount: toCountMetric(response.api.request_count),
    },
    apiKeys: {
      active: response.api_keys.active,
      activeCount: response.api_keys.active_count,
    },
    authentication: {
      averageAuthTime: toLatencyMetric(response.authentication.average_auth_time),
      failedAttempts: {
        failed: response.authentication.failed_attempts.failed,
        percent: response.authentication.failed_attempts.percent,
        total: response.authentication.failed_attempts.total,
        trend: response.authentication.failed_attempts.trend
          ? toTrend(response.authentication.failed_attempts.trend)
          : undefined,
      },
      lastLogin: response.authentication.last_login,
      successRate: toRateMetric(response.authentication.success_rate),
      successRateSeries: response.authentication.success_rate_series.map((point) => ({
        bucketStart: point.bucket_start,
        failed: point.failed,
        succeeded: point.succeeded,
        successRate: point.success_rate,
      })),
    },
    company: toCompany(response.company),
    health: response.health,
    status: response.status,
    users: toCountMetric(response.users),
    window: response.window,
  };
}

export async function getOrgMetrics(
  orgSlug: string,
  params?: GetOrgMetricsParams,
): Promise<OrgMetrics> {
  const response = await getList<OrgMetricsResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/metrics`,
    {
      params,
    },
  );

  return toOrgMetrics(response);
}

export async function getTenantMetrics(
  orgSlug: string,
  tenantSlug: string,
  params?: GetOrgMetricsParams,
): Promise<TenantMetrics> {
  const response = await getList<TenantMetricsResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/metrics`,
    {
      params,
    },
  );

  return toTenantMetrics(response);
}
