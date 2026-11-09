import { redirect } from 'next/navigation';

type TenantRootPageProps = {
  params: Promise<{ orgSlug: string; tenantSlug: string }>;
};

export default async function TenantRootPage({ params }: TenantRootPageProps) {
  const { orgSlug, tenantSlug } = await params;

  redirect(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/overview`,
  );
}
