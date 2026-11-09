import { redirect } from 'next/navigation';

type ManagedTenantOverviewPageProps = {
  params: Promise<{ tenantSlug: string }>;
};

export default async function ManagedTenantOverviewPage({
  params,
}: ManagedTenantOverviewPageProps) {
  const { tenantSlug } = await params;

  redirect(`/tenants/${encodeURIComponent(tenantSlug)}`);
}
