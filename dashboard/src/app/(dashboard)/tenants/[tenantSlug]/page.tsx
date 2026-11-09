'use client';

import { useState } from 'react';
import type { ComponentType } from 'react';
import { usePathname, useRouter } from 'next/navigation';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { AgentsCard } from '@/components/dashboard/tenant-detail/sections/agents-card';
import { ApiKeysCard } from '@/components/dashboard/tenant-detail/sections/api-keys-card';
import { ConnectionsCard } from '@/components/dashboard/tenant-detail/sections/connections-card';
import { ConnectedAccountsCard } from '@/components/dashboard/workflows/connected-accounts/connected-accounts-card';
import { MemoriesCard } from '@/components/dashboard/workflows/memories/memories-card';
import { SandboxesCard } from '@/components/dashboard/workflows/sandboxes/sandboxes-card';
import { WorkflowsCard } from '@/components/dashboard/workflows/workflows-card';
import { DomainsCard } from '@/components/dashboard/tenant-detail/sections/domains-card';
import { FlowsCard } from '@/components/dashboard/tenant-detail/sections/flows-card';
import { GroupsCard } from '@/components/dashboard/tenant-detail/sections/groups-card';
import { ModelProvidersCard } from '@/components/dashboard/tenant-detail/sections/model-providers-card';
import { OAuthClientsCard } from '@/components/dashboard/tenant-detail/sections/oauth-clients-card';
import { PipelineCard } from '@/components/dashboard/tenant-detail/sections/pipeline-card';
import { ResourceTypesCard } from '@/components/dashboard/tenant-detail/sections/roles/resource-types-card';
import { RolesCard } from '@/components/dashboard/tenant-detail/sections/roles-card';
import { RoutesCard } from '@/components/dashboard/tenant-detail/sections/routes-card';
import { ServicesCard } from '@/components/dashboard/tenant-detail/sections/services-card';
import { StreamsCard } from '@/components/dashboard/tenant-detail/sections/streams-card';
import { TenantOverviewSection } from '@/components/dashboard/tenant-detail/sections/tenant-overview-section';
import { TenantPolicySection } from '@/components/dashboard/tenant-detail/sections/tenant-policy-section';
import { TenantUsersCard } from '@/components/dashboard/tenant-detail/sections/tenant-users-card';
import { ToolsCard } from '@/components/dashboard/tenant-detail/sections/tools-card';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { getTenantManagementTabHref } from '@/utils/dashboard-nav';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import type { DashboardNavItem } from '@/types/dashboard';

const tenantSections: Record<string, ComponentType> = {
  Agents: AgentsCard,
  'API keys': ApiKeysCard,
  'Connected accounts': ConnectedAccountsCard,
  Connections: ConnectionsCard,
  Domains: DomainsCard,
  Flows: FlowsCard,
  Groups: GroupsCard,
  Memories: MemoriesCard,
  'Model Providers': ModelProvidersCard,
  'OAuth Clients': OAuthClientsCard,
  Overview: TenantOverviewSection,
  Permissions: ResourceTypesCard,
  Pipelines: PipelineCard,
  Policy: TenantPolicySection,
  Roles: RolesCard,
  Routes: RoutesCard,
  Sandboxes: SandboxesCard,
  Services: ServicesCard,
  Signals: StreamsCard,
  Tools: ToolsCard,
  Users: TenantUsersCard,
  Workflows: WorkflowsCard,
};

function PendingTenantSection() {
  return null;
}

const tenantSectionIcons: Record<string, string> = {
  Agents: 'robot_2',
  'API keys': 'key',
  'Connected accounts': 'link',
  Connections: 'link',
  Domains: 'language',
  Flows: 'account_tree',
  Groups: 'diversity_3',
  Memories: 'psychology',
  'Model Providers': 'neurology',
  'OAuth Clients': 'hub',
  Overview: 'dashboard',
  Permissions: 'fact_check',
  Pipelines: 'schema',
  // Policy: 'gavel',
  Roles: 'admin_panel_settings',
  Routes: 'route',
  Sandboxes: 'terminal',
  Services: 'dns',
  Signals: 'sensors',
  Tools: 'handyman',
  Users: 'groups',
  Workflows: 'account_tree',
};

export default function TenantDetailPage() {
  const navLabels = useNavLabels();
  const pathname = usePathname();
  const router = useRouter();
  const [activeTenantSection, setActiveTenantSection] = useState(() => {
    if (pathname.endsWith('/users')) {
      return 'Users';
    }

    if (pathname.endsWith('/groups')) {
      return 'Groups';
    }

    if (pathname.endsWith('/roles')) {
      return 'Roles';
    }

    if (pathname.endsWith('/permissions')) {
      return 'Permissions';
    }

    if (pathname.endsWith('/policy')) {
      return 'Policy';
    }

    if (pathname.endsWith('/domains')) {
      return 'Domains';
    }

    if (pathname.endsWith('/connections')) {
      return 'Connections';
    }

    if (pathname.endsWith('/api-keys')) {
      return 'API keys';
    }

    if (pathname.endsWith('/oauth-clients')) {
      return 'OAuth Clients';
    }

    if (pathname.endsWith('/streams')) {
      return 'Signals';
    }

    if (pathname.endsWith('/routes')) {
      return 'Routes';
    }

    if (pathname.endsWith('/services')) {
      return 'Services';
    }

    if (pathname.endsWith('/pipelines')) {
      return 'Pipelines';
    }

    if (pathname.endsWith('/crypto') || pathname.includes('/crypto/')) {
      return 'Crypto';
    }

    if (pathname.endsWith('/workflows')) {
      return 'Workflows';
    }

    if (pathname.endsWith('/sandboxes')) {
      return 'Sandboxes';
    }

    if (pathname.endsWith('/memories')) {
      return 'Memories';
    }

    if (pathname.endsWith('/connected-accounts')) {
      return 'Connected accounts';
    }

    if (pathname.endsWith('/agents')) {
      return 'Agents';
    }

    if (pathname.endsWith('/flows')) {
      return 'Flows';
    }

    if (pathname.endsWith('/tools')) {
      return 'Tools';
    }

    if (pathname.endsWith('/model-providers')) {
      return 'Model Providers';
    }

    return 'Overview';
  });
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);
  const headerTrail = isTenantView
    ? [
        {
          icon: tenantSectionIcons[activeTenantSection] ?? 'dashboard',
          title: navLabels.label(activeTenantSection),
        },
      ]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          onClick: handleGoToOverview,
          title: companyDisplayName,
        },
        { title: navLabels.label(activeTenantSection) },
      ];
  const ActiveTenantSection =
    tenantSections[activeTenantSection] ??
    (activeTenantSection === 'Crypto' ? PendingTenantSection : TenantOverviewSection);

  function handleTenantSectionChange(item: DashboardNavItem) {
    setActiveTenantSection(item.label);
    router.replace(getTenantManagementTabHref(tenantSlug, item.label), { scroll: false });
  }

  function handleGoToOverview() {
    setActiveTenantSection('Overview');
    router.replace(getTenantManagementTabHref(tenantSlug, 'Overview'), { scroll: false });
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel={activeTenantSection}
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <ActiveTenantSection />
        </main>
      </div>
    </div>
  );
}
