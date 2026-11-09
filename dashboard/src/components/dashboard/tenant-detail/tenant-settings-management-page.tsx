'use client';

import { useEffect, useState } from 'react';
import type { ComponentType } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { TenantClassificationSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-classification-settings-section';
import { TenantDangerZoneSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-danger-zone-settings-section';
import { TenantGeneralSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-general-settings-section';
import { TenantMtlsSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-mtls-settings-section';
import { TenantResidencySection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-residency-section';
import { TenantAuthConfigSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-auth-config-section';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { DashboardNavItem } from '@/types/dashboard';
import type { TenantPermissionResource } from '@/types/permission';
import { getTenantManagementPath, getTenantPath } from '@/utils/dashboard-routes';

type TenantSettingsTabLabel = 'General' | 'Sign-in' | 'mTLS' | 'Classification' | 'Danger zone';

const tenantSettingsTabs: {
  icon: string;
  label: TenantSettingsTabLabel;
  permission?: TenantPermissionResource;
  slug: string;
}[] = [
  { icon: 'tune', label: 'General', slug: 'general' },
  { icon: 'login', label: 'Sign-in', permission: 'AuthConfig', slug: 'sign-in' },
  { icon: 'security', label: 'mTLS', permission: 'Mtls', slug: 'mtls' },
  { icon: 'policy', label: 'Classification', permission: 'Classification', slug: 'classification' },
  {
    icon: 'dangerous',
    label: 'Danger zone',
    permission: 'TenantSettings',
    slug: 'danger-zone',
  },
];

function TenantGeneralSettingsPageSection() {
  return (
    <div className="flex w-full flex-col gap-4">
      <TenantGeneralSettingsSection />
      <TenantResidencySection />
    </div>
  );
}

const tenantSettingsSections: Record<TenantSettingsTabLabel, ComponentType> = {
  Classification: TenantClassificationSettingsSection,
  'Danger zone': TenantDangerZoneSettingsSection,
  General: TenantGeneralSettingsPageSection,
  mTLS: TenantMtlsSettingsSection,
  'Sign-in': TenantAuthConfigSection,
};

export default function TenantSettingsManagementPage() {
  const t = useTranslations('dashboard.settings');
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const router = useRouter();
  const { canView, isLoading: isLoadingPermissions } = useTenantPermissions();
  const [activeTab, setActiveTab] = useState<TenantSettingsTabLabel>(() => {
    const matchedTab = tenantSettingsTabs.find((tab) => pathname.endsWith(`/${tab.slug}`));

    return matchedTab?.label ?? 'General';
  });
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const overviewPath =
    isTenantView && orgSlug
      ? `${getTenantPath(orgSlug, tenantSlug)}/overview`
      : getTenantManagementPath(tenantSlug);
  const settingsPath =
    isTenantView && orgSlug
      ? `${getTenantPath(orgSlug, tenantSlug)}/settings`
      : `${getTenantManagementPath(tenantSlug)}/settings`;

  function isVisible(permission?: TenantPermissionResource) {
    return permission === undefined || isLoadingPermissions || canView(permission);
  }

  const visibleTabs = tenantSettingsTabs.filter((tab) => isVisible(tab.permission));
  const activeIsVisible = visibleTabs.some((tab) => tab.label === activeTab);
  const effectiveTab = activeIsVisible ? activeTab : 'General';
  const ActiveSettingsSection = tenantSettingsSections[effectiveTab];

  const navItems: DashboardNavItem[] = visibleTabs.map((tab) => ({
    href: `${settingsPath}/${tab.slug}`,
    icon: tab.icon,
    label: tab.label,
  }));

  function handleItemSelect(item: DashboardNavItem) {
    setActiveTab(item.label as TenantSettingsTabLabel);
    router.replace(item.href, { scroll: false });
  }

  useEffect(() => {
    if (pathname === settingsPath) {
      router.replace(`${settingsPath}/general`, { scroll: false });
    }
  }, [pathname, router, settingsPath]);

  const headerTrail = [
    { href: '/tenants', icon: 'corporate_fare' },
    {
      badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
      href: overviewPath,
      title: companyDisplayName,
    },
    { title: t('title') },
    { title: navLabels.label(effectiveTab) },
  ];

  const settingsSidebarHeader = (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray/70">
      {t('title')}
    </p>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <SectionSidebar
        activeLabel={effectiveTab}
        ariaLabel={t('navigation')}
        backHref={overviewPath}
        backLabel={t('back')}
        header={settingsSidebarHeader}
        headerBordered={false}
        items={navItems}
        onItemSelect={handleItemSelect}
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <div className="flex min-h-0 flex-1 justify-center overflow-y-auto px-4 py-4">
          <main className="h-full w-full min-w-0 max-w-360">
            <ActiveSettingsSection />
          </main>
        </div>
      </div>
    </div>
  );
}
