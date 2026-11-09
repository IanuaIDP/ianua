export type ActivityCategoryCount = {
  category: string;
  count: number;
};

export type ActivityDay = {
  byCategory: ActivityCategoryCount[];
  count: number;
  date: string;
  level: number;
};

export type OrgActivity = {
  categories: string[];
  days: ActivityDay[];
  from: string;
  maxCount: number;
  to: string;
  total: number;
};

export type AgentActivitySortField = 'event_type' | 'occurred_at';
export type AgentActivitySortDirection = 'asc' | 'desc';

export type AgentActivityEvent = {
  actor: string;
  details?: Record<string, unknown>;
  eventType: string;
  id: string;
  occurredAt: string;
  targetId?: string;
};

export type AgentActivityList = {
  items: AgentActivityEvent[];
  limit: number;
  nextCursor: string | null;
};
