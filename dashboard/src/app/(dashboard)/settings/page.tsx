'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import type { ComponentType } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { AccountSettingsSection } from '@/components/dashboard/settings/sections/account-settings-section';
import { ApiKeySettingsSection } from '@/components/dashboard/settings/sections/api-key-settings-section';
import { AuditLogSettingsSection } from '@/components/dashboard/settings/sections/audit-log-settings-section';
import { CloudSettingsSection } from '@/components/dashboard/settings/sections/cloud-settings-section';
import { DangerZoneSettingsSection } from '@/components/dashboard/settings/sections/danger-zone-settings-section';
import { GeneralSettingsSection } from '@/components/dashboard/settings/sections/general-settings-section';
import { OrgAuthConfigSection } from '@/components/dashboard/settings/sections/org-auth-config-section';
import { SecuritySettingsSection } from '@/components/dashboard/settings/sections/security-settings-section';
import { SubscriptionSettingsSection } from '@/components/dashboard/settings/sections/subscription-settings-section';
import {
  getVisibleSettingsNavItems,
  settingsNavItems,
} from '@/components/dashboard/settings/settings-sidebar';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { getSettingsTabHref } from '@/lib/settings/settings-routes';
import type { DashboardNavItem } from '@/types/dashboard';
import type { SettingsNavItemData } from '@/types/setting';
import type { OrgRights } from '@/utils/org-role';

const settingsSections: Record<string, ComponentType> = {
  Account: AccountSettingsSection,
  'API Key': ApiKeySettingsSection,
  'Audit Log': AuditLogSettingsSection,
  Cloud: CloudSettingsSection,
  'Danger zone': DangerZoneSettingsSection,
  General: GeneralSettingsSection,
  Security: SecuritySettingsSection,
  'Sign-in': OrgAuthConfigSection,
  Subscription: SubscriptionSettingsSection,
};

function getInitialSettingsItem(tabParam: string | null, rights: OrgRights) {
  const visibleItems = getVisibleSettingsNavItems(rights);

  return (
    visibleItems.find((item) => item.label.toLowerCase() === tabParam?.toLowerCase().trim()) ??
    visibleItems[0]
  );
}

function SettingsPageContent() {
  const t = useTranslations('dashboard.settings');
  const navLabels = useNavLabels();
  const router = useRouter();
  const searchParams = useSearchParams();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const orgRights = useOrgAccess();
  const [requestedSettingsItem, setRequestedSettingsItem] = useState(() =>
    getInitialSettingsItem(searchParams.get('tab'), orgRights),
  );
  const activeSettingsItem =
    requestedSettingsItem.requires && !orgRights[requestedSettingsItem.requires]
      ? settingsNavItems[0]
      : requestedSettingsItem;
  const ActiveSettingsSection = settingsSections[activeSettingsItem.label];

  const navItems: DashboardNavItem[] = getVisibleSettingsNavItems(orgRights).map((item) => ({
    href: getSettingsTabHref(item.label),
    icon: item.icon,
    label: item.label,
  }));

  function handleSettingsItemSelect(item: DashboardNavItem) {
    const matchedItem: SettingsNavItemData =
      settingsNavItems.find((navItem) => navItem.label === item.label) ?? settingsNavItems[0];

    setRequestedSettingsItem(matchedItem);
    router.replace(item.href, { scroll: false });
    scrollContainerRef.current?.scrollTo({ top: 0 });
  }

  useEffect(() => {
    if (!searchParams.get('tab')) {
      router.replace(getSettingsTabHref(activeSettingsItem.label), { scroll: false });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const headerTrail = [{ title: navLabels.label(activeSettingsItem.label) }];

  const settingsSidebarHeader = (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray/70">
      {t('title')}
    </p>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <SectionSidebar
        activeLabel={activeSettingsItem.label}
        ariaLabel={t('navigation')}
        backHref="/overview"
        backLabel={t('back')}
        header={settingsSidebarHeader}
        headerBordered={false}
        items={navItems}
        onItemSelect={handleSettingsItemSelect}
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <div
          ref={scrollContainerRef}
          className="flex min-h-0 flex-1 justify-center overflow-y-auto px-4 py-4"
        >
          <main className="h-full w-full min-w-0 max-w-360">
            <ActiveSettingsSection />
          </main>
        </div>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <Suspense>
      <SettingsPageContent />
    </Suspense>
  );
}
