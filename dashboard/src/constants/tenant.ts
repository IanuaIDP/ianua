// The warning lists of the tenant lifecycle modals; the text of each id is in
// messages/<language>.json under dashboard.tenants.dangerZone.
export const SUSPEND_TENANT_WARNING_IDS = ['sessions', 'data', 'reactivate'] as const;

export const DELETE_TENANT_REMOVED_IDS = [
  'settings',
  'users',
  'rolesPermissions',
  'domains',
  'apiKeys',
  'oauthClients',
  'routes',
  'auditLogs',
  'allData',
] as const;

export const ARCHIVE_TENANT_WARNING_IDS = [
  'access',
  'sessions',
  'lists',
  'noRestore',
  'newOne',
] as const;
