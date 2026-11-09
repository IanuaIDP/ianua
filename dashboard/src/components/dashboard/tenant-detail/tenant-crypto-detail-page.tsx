'use client';

import { useRef, useState } from 'react';
import type { ComponentType } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { CryptoJwksCard } from '@/components/dashboard/tenant-detail/sections/crypto-jwks-card';
import { CryptoKeysCard } from '@/components/dashboard/tenant-detail/sections/crypto-keys-card';
import { CryptoMigrationCard } from '@/components/dashboard/tenant-detail/sections/crypto-migration-card';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { DashboardNavItem } from '@/types/dashboard';
import { getTenantCryptoNavItems } from '@/utils/dashboard-nav';
import { getTenantManagementPath, getTenantPath } from '@/utils/dashboard-routes';

type TenantCryptoSectionLabel = 'Keys' | 'Migration' | 'JWKS';

function CryptoKeysSection() {
  return <CryptoKeysCard />;
}

function CryptoMigrationSection() {
  return <CryptoMigrationCard />;
}

function CryptoJwksSection() {
  return <CryptoJwksCard />;
}

const tenantCryptoSections: Record<TenantCryptoSectionLabel, ComponentType> = {
  JWKS: CryptoJwksSection,
  Keys: CryptoKeysSection,
  Migration: CryptoMigrationSection,
};

function getActiveCryptoSection(pathname: string): TenantCryptoSectionLabel {
  if (pathname.endsWith('/migration')) {
    return 'Migration';
  }

  if (pathname.endsWith('/jwks')) {
    return 'JWKS';
  }

  return 'Keys';
}

export default function TenantCryptoDetailPage() {
  const t = useTranslations('dashboard.crypto');
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const router = useRouter();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const [activeCryptoSection, setActiveCryptoSection] = useState<TenantCryptoSectionLabel>(() =>
    getActiveCryptoSection(pathname),
  );
  const navItems = getTenantCryptoNavItems(isTenantView ? orgSlug : undefined, tenantSlug);
  const ActiveCryptoSection = tenantCryptoSections[activeCryptoSection];
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const overviewPath =
    isTenantView && orgSlug
      ? `${getTenantPath(orgSlug, tenantSlug)}/overview`
      : getTenantManagementPath(tenantSlug);
  const headerTrail = isTenantView
    ? [{ title: navLabels.label(activeCryptoSection) }]
    : [
        { href: '/tenants', icon: 'corporate_fare' },
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { title: navLabels.label('Crypto') },
        { title: navLabels.label(activeCryptoSection) },
      ];

  function handleSectionChange(item: DashboardNavItem) {
    setActiveCryptoSection(item.label as TenantCryptoSectionLabel);
    router.replace(item.href, { scroll: false });
    scrollContainerRef.current?.scrollTo({ top: 0 });
  }

  const cryptoSidebarHeader = (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray/70">
      {navLabels.label('Crypto')}
    </p>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <SectionSidebar
        activeLabel={activeCryptoSection}
        ariaLabel={t('navigation')}
        backHref={overviewPath}
        backLabel={t('back')}
        header={cryptoSidebarHeader}
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
          <main className="flex w-full min-w-0 max-w-360 flex-col gap-4">
            <ActiveCryptoSection />
          </main>
        </div>
      </div>
    </div>
  );
}
