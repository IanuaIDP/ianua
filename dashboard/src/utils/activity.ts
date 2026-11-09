import type { AgentActivityEvent } from '@/types/activity';

type ActivityTone = 'error' | 'info' | 'success' | 'warning';

const TONE_ICON: Record<ActivityTone, string> = {
  error: 'error',
  info: 'info',
  success: 'check_circle',
  warning: 'warning',
};

const TONE_COLOR: Record<ActivityTone, string> = {
  error: 'text-error',
  info: 'text-textGray',
  success: 'text-primary',
  warning: 'text-orange',
};

export function formatActivityTitle(eventType: string) {
  const words = eventType
    .split(/[._-]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());

  if (words.length === 0) {
    return eventType;
  }

  const sentence = words.join(' ');

  return sentence.charAt(0).toUpperCase() + sentence.slice(1);
}

function getActivityTone(eventType: string): ActivityTone {
  const normalized = eventType.toLowerCase();

  if (/(fail|denied|deny|error|revoked|expired|reject)/.test(normalized)) {
    return 'error';
  }

  if (/(awaiting|pending|paused|warn)/.test(normalized)) {
    return 'warning';
  }

  if (/(approved|granted|completed|succeeded|success|allowed)/.test(normalized)) {
    return 'success';
  }

  return 'info';
}

export function getActivityIcon(eventType: string) {
  const tone = getActivityTone(eventType);

  return { className: TONE_COLOR[tone], icon: TONE_ICON[tone] };
}

function toSummaryValue(value: unknown): string {
  if (value === null || value === undefined || value === '') {
    return '—';
  }

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  if (typeof value === 'object' && 'label' in (value as Record<string, unknown>)) {
    return String((value as Record<string, unknown>).label);
  }

  return JSON.stringify(value);
}

export type ActivitySummaryEntry = {
  key: string;
  value: string;
};

export function getActivitySummary(event: AgentActivityEvent): ActivitySummaryEntry[] {
  if (!event.details) {
    return [];
  }

  const entries = Object.entries(event.details).filter(
    ([, value]) => value !== null && value !== undefined,
  );

  return entries
    .slice(0, 3)
    .map(([key, value]) => ({ key: key.replace(/_/g, ' '), value: toSummaryValue(value) }));
}
