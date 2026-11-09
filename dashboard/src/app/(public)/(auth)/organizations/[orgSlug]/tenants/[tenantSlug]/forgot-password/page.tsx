import { ForgotPasswordContent } from '@/app/(public)/(auth)/forgot-password/page';
import { getTenantPath } from '@/utils/dashboard-routes';

type TenantForgotPasswordPageProps = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export default async function TenantForgotPasswordPage({ params }: TenantForgotPasswordPageProps) {
  const { orgSlug, tenantSlug } = await params;
  const tenantPath = getTenantPath(orgSlug, tenantSlug);

  return (
    <ForgotPasswordContent
      backToLoginHref={`${tenantPath}/login`}
      tenantContext={{ orgSlug, tenantSlug }}
    />
  );
}
