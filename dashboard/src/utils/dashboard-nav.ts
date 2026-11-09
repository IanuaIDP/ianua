import {
  getAgentManagementPath,
  getAgentPath,
  getTenantManagementPath,
  getTenantPath,
} from '@/utils/dashboard-routes';
import { DashboardNavItem, NavSegment } from '@/types/dashboard';

function getTenantNavItemsByBasePath(tenantPath: string): DashboardNavItem[] {
  return [
    { href: `${tenantPath}/overview`, label: 'Overview', icon: 'dashboard' },
    { activeMatch: 'nested', href: `${tenantPath}/users`, label: 'Users', icon: 'groups' },
    {
      activeMatch: 'nested',
      href: `${tenantPath}/groups`,
      label: 'Groups',
      icon: 'diversity_3',
    },
    {
      activeMatch: 'nested',
      href: `${tenantPath}/roles`,
      label: 'Roles',
      icon: 'shield_person',
    },
    {
      activeMatch: 'nested',
      href: `${tenantPath}/permissions`,
      label: 'Permissions',
      icon: 'fact_check',
    },
    {
      activeMatch: 'nested',
      href: `${tenantPath}/policy`,
      label: 'Policy',
      icon: 'gavel',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/domains`,
      label: 'Domains',
      icon: 'language',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/connections`,
      label: 'Connections',
      icon: 'link',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/api-keys`,
      label: 'API keys',
      icon: 'key',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/oauth-clients`,
      label: 'OAuth Clients',
      icon: 'hub',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/streams`,
      label: 'Signals',
      icon: 'sensors',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/services`,
      label: 'Services',
      icon: 'dns',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/routes`,
      label: 'Routes',
      icon: 'route',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/pipelines`,
      label: 'Pipelines',
      icon: 'schema',
    },
    {
      activeMatch: 'nested',
      group: 'Infrastructure',
      href: `${tenantPath}/crypto`,
      label: 'Crypto',
      icon: 'token',
    },
    {
      activeMatch: 'nested',
      group: 'Automation',
      href: `${tenantPath}/workflows`,
      label: 'Workflows',
      icon: 'account_tree',
    },
    {
      activeMatch: 'nested',
      group: 'Automation',
      href: `${tenantPath}/sandboxes`,
      label: 'Sandboxes',
      icon: 'terminal',
    },
    {
      activeMatch: 'nested',
      group: 'Automation',
      href: `${tenantPath}/memories`,
      label: 'Memories',
      icon: 'psychology',
    },
    {
      activeMatch: 'nested',
      group: 'Automation',
      href: `${tenantPath}/connected-accounts`,
      label: 'Connected accounts',
      icon: 'link',
    },
    {
      activeMatch: 'nested',
      group: 'Agents',
      href: `${tenantPath}/agents`,
      label: 'Agents',
      icon: 'robot_2',
    },
    {
      activeMatch: 'nested',
      group: 'Agents',
      href: `${tenantPath}/flows`,
      label: 'Flows',
      icon: 'account_tree',
    },
    {
      activeMatch: 'nested',
      group: 'Agents',
      href: `${tenantPath}/tools`,
      label: 'Tools',
      icon: 'handyman',
    },
    {
      activeMatch: 'nested',
      group: 'Agents',
      href: `${tenantPath}/model-providers`,
      label: 'Model Providers',
      icon: 'neurology',
    },
  ];
}

export function getTenantNavItems(orgSlug: string, tenantSlug: string): DashboardNavItem[] {
  return getTenantNavItemsByBasePath(getTenantPath(orgSlug, tenantSlug));
}

export function getTenantManagementNavItems(tenantSlug: string): DashboardNavItem[] {
  const tenantPath = getTenantManagementPath(tenantSlug);

  return [
    { href: tenantPath, label: 'Overview', icon: 'dashboard' },
    ...getTenantNavItemsByBasePath(tenantPath).slice(1),
    {
      activeMatch: 'nested',
      href: `${tenantPath}/settings/general`,
      label: 'Settings',
      icon: 'settings',
    },
  ];
}

export function getAgentDetailNavItems(
  orgSlug: string | undefined,
  tenantSlug: string,
  agentId: string,
): DashboardNavItem[] {
  const agentPath = orgSlug
    ? getAgentPath(orgSlug, tenantSlug, agentId)
    : getAgentManagementPath(tenantSlug, agentId);

  // Governing an agent stays on sight: who it is, what it may reach, what is
  // waiting on a person, and what it did. Running one is a different job, so
  // Runs sits under Operations alongside the key maintenance nobody needs on a
  // first visit.
  //
  // Approvals is deliberately not down there. A grant can pause every action
  // until someone approves it, so the place to unpause has to be visible — or
  // the agent simply looks stuck.
  return [
    { href: `${agentPath}/overview`, label: 'Overview', icon: 'dashboard' },
    {
      activeMatch: 'nested',
      href: `${agentPath}/delegations`,
      label: 'Access',
      icon: 'admin_panel_settings',
    },
    {
      activeMatch: 'nested',
      href: `${agentPath}/approvals`,
      label: 'Approvals',
      icon: 'assignment_turned_in',
    },
    {
      activeMatch: 'nested',
      href: `${agentPath}/channels`,
      label: 'Channels',
      icon: 'swap_horiz',
    },
    { activeMatch: 'nested', href: `${agentPath}/activity`, label: 'Activity', icon: 'article' },
    {
      activeMatch: 'nested',
      group: 'Operations',
      href: `${agentPath}/runs`,
      label: 'Runs',
      icon: 'play_circle',
    },
    {
      activeMatch: 'nested',
      group: 'Operations',
      href: `${agentPath}/credentials`,
      label: 'Credentials',
      icon: 'key',
    },
  ];
}

export function getTenantSettingsNavItems(orgSlug: string, tenantSlug: string): DashboardNavItem[] {
  const settingsPath = `${getTenantPath(orgSlug, tenantSlug)}/settings`;

  return [
    { href: `${settingsPath}/general`, label: 'General', icon: 'tune' },
    { href: `${settingsPath}/account`, label: 'Account', icon: 'account_circle' },
    { href: `${settingsPath}/security`, label: 'Security', icon: 'encrypted' },
    { href: `${settingsPath}/sign-in`, label: 'Sign-in', icon: 'login' },
    { href: `${settingsPath}/mtls`, label: 'mTLS', icon: 'security' },
    { href: `${settingsPath}/classification`, label: 'Classification', icon: 'policy' },
  ];
}

export function getTenantCryptoNavItems(orgSlug: string | undefined, tenantSlug: string) {
  const cryptoPath = orgSlug
    ? `${getTenantPath(orgSlug, tenantSlug)}/crypto`
    : `${getTenantManagementPath(tenantSlug)}/crypto`;

  return [
    { href: `${cryptoPath}/keys`, label: 'Keys', icon: 'key' },
    { href: `${cryptoPath}/migration`, label: 'Migration', icon: 'swap_horiz' },
    { href: `${cryptoPath}/jwks`, label: 'JWKS', icon: 'data_object' },
  ] satisfies DashboardNavItem[];
}

export function getTenantManagementTabHref(tenantSlug: string, label: string) {
  const item = getTenantManagementNavItems(tenantSlug).find((navItem) => navItem.label === label);

  return item?.href ?? getTenantManagementPath(tenantSlug);
}

export function isNavItemActive(pathname: string, item: DashboardNavItem) {
  if (pathname === item.href) {
    return true;
  }

  return item.activeMatch === 'nested' && pathname.startsWith(`${item.href}/`);
}

export function buildNavSegments(items: DashboardNavItem[]): NavSegment[] {
  const segments: NavSegment[] = [];

  for (const item of items) {
    const lastSegment = segments[segments.length - 1];

    if (item.group && lastSegment?.type === 'group' && lastSegment.group === item.group) {
      lastSegment.items.push(item);
      continue;
    }

    segments.push(
      item.group ? { type: 'group', group: item.group, items: [item] } : { type: 'item', item },
    );
  }

  return segments;
}

export function getFirstGroup(items: DashboardNavItem[]) {
  return items.find((item) => item.group)?.group ?? null;
}
