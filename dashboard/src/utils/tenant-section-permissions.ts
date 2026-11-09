import type { DashboardNavItem } from '@/types/dashboard';
import type { TenantPermissionAction, TenantPermissionResource } from '@/types/permission';

// Which permission resource a tenant section needs before it is shown. Any
// permission on the resource (view, update, manage, …) is enough to see it.
// Sections not listed (Overview, Settings, Notifications, Account) are not
// gated here; settings pages gate themselves per tab.
const tenantSectionResource: Partial<Record<string, TenantPermissionResource>> = {
  agents: 'Agents',
  'api-keys': 'ApiKeys',
  connections: 'Federation',
  'connected-accounts': 'Workflows',
  crypto: 'Crypto',
  domains: 'Domains',
  flows: 'Workflows',
  groups: 'Roles',
  memories: 'Workflows',
  'model-providers': 'Agents',
  'oauth-clients': 'ApiKeys',
  permissions: 'Roles',
  pipelines: 'Pipeline',
  policy: 'PolicySet',
  roles: 'Roles',
  routes: 'Routing',
  sandboxes: 'Workflows',
  services: 'Routing',
  'stream-routes': 'Routing',
  streams: 'Signals',
  tools: 'Agents',
  users: 'Users',
  workflows: 'Workflows',
};

const tenantSectionPattern = /^(?:\/organizations\/[^/]+)?\/tenants\/[^/]+\/([^/]+)/;

function getSectionFromHref(href: string) {
  return href.match(tenantSectionPattern)?.[1] ?? null;
}

/** The resource required by the tenant section at `pathname`, if any. */
export function getTenantSectionResource(pathname: string): TenantPermissionResource | null {
  const section = getSectionFromHref(pathname);

  return (section && tenantSectionResource[section]) || null;
}

const tenantFormPatterns: {
  pattern: RegExp;
  resource: TenantPermissionResource;
  action: TenantPermissionAction;
}[] = [
  {
    action: 'Create',
    pattern: /\/(routes|services|stream-routes)\/create\/?$/,
    resource: 'Routing',
  },
  {
    action: 'Update',
    pattern: /\/(routes|services|stream-routes)\/[^/]+\/edit\/?$/,
    resource: 'Routing',
  },
  { action: 'Create', pattern: /\/flows\/create\/?$/, resource: 'Workflows' },
];

/** The permission a create or edit page needs, beyond seeing its section. */
export function getTenantFormPermission(pathname: string) {
  return tenantFormPatterns.find(({ pattern }) => pattern.test(pathname)) ?? null;
}

/** Drops tenant nav items whose section the user may not see. */
export function filterTenantNavItemsByPermission(
  items: DashboardNavItem[],
  canView: (resource: TenantPermissionResource) => boolean,
) {
  return items.filter((item) => {
    const resource = getTenantSectionResource(item.href);

    return !resource || canView(resource);
  });
}
