'use client';

import { useTranslations } from 'next-intl';

import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { getTenantManagementNavItems, getTenantNavItems } from '@/utils/dashboard-nav';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { filterTenantNavItemsByPermission } from '@/utils/tenant-section-permissions';
import { DashboardNavItem } from '@/types/dashboard';

const tenantSidebarItems: DashboardNavItem[] = [
  { href: '#overview', icon: 'dashboard', isActive: true, label: 'Overview' },
  { href: '#users', icon: 'groups', label: 'Users' },
  { href: '#roles', icon: 'admin_panel_settings', label: 'Roles' },
  { href: '#permissions', icon: 'fact_check', label: 'Permissions' },
  { href: '#domains', icon: 'language', label: 'Domains' },
  { href: '#connections', icon: 'link', label: 'Connections' },
  { href: '#api-keys', icon: 'key', label: 'API keys' },
  { href: '#routes', icon: 'route', label: 'Routes' },
  { href: '#crypto', icon: 'token', label: 'Crypto' },
  { href: '#agents', icon: 'robot_2', label: 'Agents' },
  { href: '#flows', icon: 'account_tree', label: 'Flows' },
  { href: '#tools', icon: 'handyman', label: 'Tools' },
  { href: '#model-providers', icon: 'neurology', label: 'Model Providers' },
  { href: '#settings', icon: 'settings', label: 'Settings' },
];

type TenantSidebarProps = {
  orgSlug?: string;
  tenantSlug?: string;
  activeLabel?: string;
  className?: string;
  onItemSelect?: (item: DashboardNavItem) => void;
  variant?: 'management' | 'tenant';
};

export function TenantSidebar({
  orgSlug,
  tenantSlug,
  activeLabel,
  className,
  onItemSelect,
  variant = 'tenant',
}: TenantSidebarProps) {
  const t = useTranslations('dashboard.nav');
  const hasTenantSlug = Boolean(tenantSlug);
  const hasTenantRoute = variant === 'tenant' ? Boolean(orgSlug && tenantSlug) : hasTenantSlug;
  const { canView } = useTenantPermissions();
  const items = hasTenantRoute
    ? filterTenantNavItemsByPermission(
        variant === 'tenant'
          ? getTenantNavItems(orgSlug ?? '', tenantSlug ?? '')
          : getTenantManagementNavItems(tenantSlug ?? ''),
        canView,
      )
    : tenantSidebarItems;

  const isManagementView = variant === 'management';

  return (
    <SectionSidebar
      activeLabel={activeLabel}
      ariaLabel={t('tenantAriaLabel')}
      backHref={isManagementView ? '/tenants' : undefined}
      backLabel={isManagementView ? t('allTenants') : undefined}
      items={items}
      onItemSelect={onItemSelect}
      className={className}
    />
  );
}
