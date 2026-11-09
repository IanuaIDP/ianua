export type AuditLogSortField = 'event_type' | 'occurred_at';
export type AuditLogSortDirection = 'asc' | 'desc';

export type AuditLogEntry = {
  /** The workflow run or impersonation the change came through, when there was one. */
  actedThrough?: string;
  actor: string;
  actorEmail?: string;
  dateTime: string;
  details?: Record<string, unknown>;
  event: string;
  eventScope: string;
  id: string;
  ip: string;
  tenantSlug?: string;
};

export type AuditExportStatus = 'pending' | 'ready' | 'failed' | 'expired';

export type AuditExport = {
  /** A signed link that works once, while the export is ready. */
  downloadUrl?: string;
  status: AuditExportStatus;
};

export type AuditLogList = {
  items: AuditLogEntry[];
  limit: number;
  nextCursor: string | null;
};

export type DetailRow = {
  key: string;
  value: string;
};
