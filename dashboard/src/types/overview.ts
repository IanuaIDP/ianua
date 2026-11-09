export type ChangeTone = 'up' | 'down' | 'flat';

export type OverviewMetricItem = {
  label: string;
  value: string;
  change: string;
  tone: ChangeTone;
};

export type TrendDirection = 'up' | 'down' | 'flat' | (string & {});

export type Trend = {
  changePct?: number | null;
  direction: TrendDirection;
};

export type CountMetric = {
  current?: number | null;
  trend: Trend;
};

export type LatencyMetric = {
  currentMs?: number | null;
  trend: Trend;
};

export type RateMetric = {
  current?: number | null;
  trend: Trend;
};

export type FailedAttemptsMetric = {
  failed?: number | null;
  percent?: number | null;
  total?: number | null;
  trend?: Trend;
};

export type SuccessRatePoint = {
  bucketStart: string;
  failed: number;
  succeeded: number;
  successRate?: number | null;
};

export type AuthenticationMetrics = {
  averageAuthTime: LatencyMetric;
  failedAttempts: FailedAttemptsMetric;
  successRate: RateMetric;
  successRateSeries: SuccessRatePoint[];
  lastLogin?: string | null;
};

export type ApiUsageMetrics = {
  errorRate: RateMetric;
  p95Latency: LatencyMetric;
  requestCount: CountMetric;
};

export type OrgMetrics = {
  activeSessions: CountMetric;
  api: ApiUsageMetrics;
  authentication: AuthenticationMetrics;
  tenants: CountMetric;
  users: CountMetric;
  window: {
    end: string;
    start: string;
  };
};

export type Company = {
  contactEmail?: string | null;
  createdAt?: string | null;
  displayName: string;
  locale?: string | null;
  primaryDomain?: string | null;
  slug: string;
  timezone?: string | null;
};

export type TenantMetrics = {
  activeSessions: CountMetric;
  activeUsers: CountMetric;
  api: ApiUsageMetrics;
  apiKeys: {
    active: boolean;
    activeCount?: number | null;
  };
  authentication: AuthenticationMetrics;
  company: Company;
  health?: number | null;
  status: string;
  users: CountMetric;
  window: {
    end: string;
    start: string;
  };
};
