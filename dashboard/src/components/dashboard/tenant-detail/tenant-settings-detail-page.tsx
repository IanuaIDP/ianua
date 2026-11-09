'use client';

import type { ComponentType } from 'react';
import { useEffect, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { TenantAccountSection } from '@/components/dashboard/tenant-detail/sections/tenant-account-section';
import { TenantClassificationSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-classification-settings-section';
import { TenantAuthConfigSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-auth-config-section';
import { TenantDangerZoneSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-danger-zone-settings-section';
import { TenantGeneralSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-general-settings-section';
import { TenantMtlsSettingsSection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-mtls-settings-section';
import { TenantResidencySection } from '@/components/dashboard/tenant-detail/sections/settings/tenant-residency-section';
import { TenantSecuritySection } from '@/components/dashboard/tenant-detail/sections/tenant-security-section';
import { useNotification } from '@/components/ui/notifications';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { DashboardNavItem } from '@/types/dashboard';
import type { TenantPermissionResource } from '@/types/permission';
import { getTenantSettingsNavItems } from '@/utils/dashboard-nav';
import { getTenantPath } from '@/utils/dashboard-routes';

type TenantSettingsSectionLabel =
  'Account' | 'Classification' | 'General' | 'Sign-in' | 'mTLS' | 'Security';

function TenantGeneralSettingsPageSection() {
  return (
    <div className="flex w-full flex-col gap-4">
      <TenantGeneralSettingsSection />
      <TenantResidencySection />
      <TenantDangerZoneSettingsSection />
    </div>
  );
}

const viewPermissionBySection: Partial<
  Record<TenantSettingsSectionLabel, TenantPermissionResource>
> = {
  Classification: 'Classification',
  General: 'TenantSettings',
  'Sign-in': 'AuthConfig',
  mTLS: 'Mtls',
};

const tenantSettingsSections: Record<TenantSettingsSectionLabel, ComponentType> = {
  Account: TenantAccountSection,
  Classification: TenantClassificationSettingsSection,
  General: TenantGeneralSettingsPageSection,
  'Sign-in': TenantAuthConfigSection,
  mTLS: TenantMtlsSettingsSection,
  Security: TenantSecuritySection,
};

export default function TenantSettingsDetailPage() {
  const t = useTranslations('dashboard.settings');
  const tLayout = useTranslations('dashboard.layout');
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const router = useRouter();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { showNotification } = useNotification();
  const { canView, isLoading: isLoadingPermissions } = useTenantPermissions();
  const [activeSettingsSection, setActiveSettingsSection] = useState<TenantSettingsSectionLabel>(
    () => {
      if (pathname.endsWith('/account')) {
        return 'Account';
      }

      if (pathname.endsWith('/security')) {
        return 'Security';
      }

      if (pathname.endsWith('/mtls')) {
        return 'mTLS';
      }

      if (pathname.endsWith('/sign-in')) {
        return 'Sign-in';
      }

      if (pathname.endsWith('/classification')) {
        return 'Classification';
      }

      if (pathname.endsWith('/general')) {
        return 'General';
      }

      return 'Account';
    },
  );

  const requiredPermission = viewPermissionBySection[activeSettingsSection];
  const isBlocked =
    !isLoadingPermissions && requiredPermission !== undefined && !canView(requiredPermission);
  const isPendingPermission = isLoadingPermissions && requiredPermission !== undefined;
  const effectiveSettingsSection = isBlocked ? 'Account' : activeSettingsSection;

  useEffect(() => {
    if (!isBlocked) {
      return;
    }

    showNotification({ message: t('tabNotAllowed'), type: 'error' });
    router.replace(`${getTenantPath(orgSlug ?? '', tenantSlug)}/settings/account`, {
      scroll: false,
    });
  }, [isBlocked, orgSlug, router, showNotification, t, tenantSlug]);

  const ActiveSettingsSection = tenantSettingsSections[effectiveSettingsSection];
  const navItems = orgSlug
    ? getTenantSettingsNavItems(orgSlug, tenantSlug).filter((item) => {
        const permission = viewPermissionBySection[item.label as TenantSettingsSectionLabel];

        return permission === undefined || canView(permission);
      })
    : [];

  function handleSectionChange(item: DashboardNavItem) {
    setActiveSettingsSection(item.label as TenantSettingsSectionLabel);
    router.replace(item.href, { scroll: false });
    scrollContainerRef.current?.scrollTo({ top: 0 });
  }

  const overviewPath = `${getTenantPath(orgSlug ?? '', tenantSlug)}/overview`;
  const headerTrail = [{ title: navLabels.label(effectiveSettingsSection) }];

  const settingsSidebarHeader = (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray/70">
      {t('title')}
    </p>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <SectionSidebar
        activeLabel={effectiveSettingsSection}
        ariaLabel={t('navigation')}
        backHref={overviewPath}
        backLabel={t('back')}
        header={settingsSidebarHeader}
        headerBordered={false}
        items={navItems}
        onItemSelect={handleSectionChange}
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <div
          ref={scrollContainerRef}
          className="flex min-h-0 flex-1 justify-center overflow-y-auto px-4 py-4"
        >
          <main className="h-full w-full min-w-0 max-w-360">
            {isPendingPermission ? (
              <p className="py-10 text-center text-xs font-medium text-textGray">
                {tLayout('loading')}
              </p>
            ) : (
              <ActiveSettingsSection />
            )}
          </main>
        </div>
      </div>
    </div>
  );
}
