'use client';

import { useRef, useState } from 'react';
import type { ComponentType } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { SectionSidebar } from '@/components/dashboard/shared/section-sidebar';
import { ActivitySection } from '@/components/dashboard/tenant-detail/sections/agents/activity-section';
import { AgentOverviewSection } from '@/components/dashboard/tenant-detail/sections/agents/agent-overview-section';
import { ApprovalsSection } from '@/components/dashboard/tenant-detail/sections/agents/approvals-section';
import { ChannelsSection } from '@/components/dashboard/tenant-detail/sections/agents/channels-section';
import { CredentialsSection } from '@/components/dashboard/tenant-detail/sections/agents/credentials-section';
import { DelegationsSection } from '@/components/dashboard/tenant-detail/sections/agents/delegations-section';
import { RunsSection } from '@/components/dashboard/tenant-detail/sections/agents/runs-section';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { getTenantAgent } from '@/lib/api';
import type { DashboardNavItem } from '@/types/dashboard';
import { getAgentDetailNavItems } from '@/utils/dashboard-nav';
import {
  getAgentManagementPath,
  getAgentPath,
  getTenantScopedPath,
} from '@/utils/dashboard-routes';

const agentSections: Record<string, ComponentType> = {
  Activity: ActivitySection,
  Approvals: ApprovalsSection,
  Channels: ChannelsSection,
  Credentials: CredentialsSection,
  Access: DelegationsSection,
  Overview: AgentOverviewSection,
  Runs: RunsSection,
};

export default function AgentDetailPage() {
  const t = useTranslations('dashboard.agents');
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const router = useRouter();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const { agentId, isTenantView, orgSlug, tenantSlug } = useAgentRouteParams();
  const [activeAgentSection, setActiveAgentSection] = useState(() => {
    if (pathname.endsWith('/delegations')) {
      return 'Access';
    }

    if (pathname.endsWith('/credentials')) {
      return 'Credentials';
    }

    if (pathname.endsWith('/channels')) {
      return 'Channels';
    }

    if (pathname.endsWith('/runs')) {
      return 'Runs';
    }

    if (pathname.endsWith('/approvals')) {
      return 'Approvals';
    }

    if (pathname.endsWith('/activity')) {
      return 'Activity';
    }

    return 'Overview';
  });

  const { data: agent } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && agentId),
    queryFn: () => getTenantAgent(orgSlug ?? '', tenantSlug, agentId),
    queryKey: ['tenant-agent', orgSlug, tenantSlug, agentId],
  });

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const ActiveAgentSection = agentSections[activeAgentSection] ?? AgentOverviewSection;
  const navItems = getAgentDetailNavItems(isTenantView ? orgSlug : undefined, tenantSlug, agentId);

  const agentsPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'agents', 'agents');
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const agentDetailPath = isTenantView
    ? orgSlug
      ? getAgentPath(orgSlug, tenantSlug, agentId)
      : undefined
    : getAgentManagementPath(tenantSlug, agentId);

  function handleSectionChange(item: DashboardNavItem) {
    setActiveAgentSection(item.label);
    router.replace(item.href, { scroll: false });
    scrollContainerRef.current?.scrollTo({ top: 0 });
  }

  const headerTrail = isTenantView
    ? [
        { href: agentsPath, icon: 'robot_2' },
        {
          badge: agent ? <DashboardStatusBadge status={agent.status} /> : undefined,
          href: agentDetailPath,
          title: agent?.name ?? t('fallbackName'),
        },
        { title: navLabels.label(activeAgentSection) },
      ]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: agentsPath, title: navLabels.label('Agents') },
        { href: agentDetailPath, title: agent?.name ?? t('fallbackName') },
        { title: navLabels.label(activeAgentSection) },
      ];

  const agentSidebarHeader = (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-textGray/70">
      {agent?.name ?? t('fallbackName')}
    </p>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <SectionSidebar
        activeLabel={activeAgentSection}
        ariaLabel={t('navigation')}
        backHref={agentsPath}
        backLabel={t('back')}
        header={agentSidebarHeader}
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
          <main className="w-full min-w-0 max-w-360">
            <ActiveAgentSection />
          </main>
        </div>
      </div>
    </div>
  );
}
