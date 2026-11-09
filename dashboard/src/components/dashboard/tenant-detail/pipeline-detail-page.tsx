'use client';

import { useQuery } from '@tanstack/react-query';

import { DashboardPageHeader } from '@/components/dashboard/dashboard-page-header';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { PipelineDetail } from '@/components/dashboard/tenant-detail/sections/pipeline/pipeline-detail';
import { TenantSidebar } from '@/components/dashboard/tenant-detail/tenant-sidebar';
import { useNavLabels } from '@/hooks/i18n/use-nav-labels';
import { usePipelineRouteParams } from '@/hooks/tenants/use-pipeline-route-params';
import { useTenantHeaderInfo } from '@/hooks/tenants/use-tenant-header-info';
import { useTenantSectionNavigation } from '@/hooks/tenants/use-tenant-section-navigation';
import { getTenantPipeline } from '@/lib/api';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

export default function PipelineDetailPage() {
  const navLabels = useNavLabels();
  const { isTenantView, orgSlug, pipelineId, tenantSlug } = usePipelineRouteParams();

  const pipelinesPath = getTenantScopedPath(
    isTenantView,
    orgSlug,
    tenantSlug,
    'pipelines',
    'pipelines',
  );
  const overviewPath = getTenantScopedPath(isTenantView, orgSlug, tenantSlug, 'overview');

  const { companyDisplayName, tenantStatus } = useTenantHeaderInfo(orgSlug, tenantSlug);

  const { data: pipeline } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && pipelineId),
    queryFn: () => getTenantPipeline(orgSlug ?? '', tenantSlug, pipelineId),
    queryKey: ['tenant-pipeline', orgSlug, tenantSlug, pipelineId],
  });

  const headerTrail = isTenantView
    ? [{ href: pipelinesPath, icon: 'schema' }, { title: pipeline?.name }]
    : [
        {
          badge: tenantStatus ? <DashboardStatusBadge status={tenantStatus} /> : undefined,
          href: overviewPath,
          title: companyDisplayName,
        },
        { href: pipelinesPath, title: navLabels.label('Pipelines') },
        { title: pipeline?.name },
      ];

  const handleTenantSectionChange = useTenantSectionNavigation(tenantSlug);

  return (
    <div className="flex h-screen overflow-hidden">
      {!isTenantView ? (
        <TenantSidebar
          activeLabel="Pipelines"
          tenantSlug={tenantSlug}
          variant="management"
          onItemSelect={handleTenantSectionChange}
        />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <DashboardPageHeader trail={headerTrail} />

        <main className="min-h-0 min-w-0 flex-1 overflow-auto px-4 py-4">
          <PipelineDetail pipelineId={pipelineId} />
        </main>
      </div>
    </div>
  );
}
