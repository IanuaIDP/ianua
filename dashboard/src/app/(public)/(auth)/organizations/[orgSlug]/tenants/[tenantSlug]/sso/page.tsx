import { AuthLayout } from '@/components/auth/AuthLayout';
import { SsoCompletion } from '@/components/auth/sso-completion';

type TenantSsoPageProps = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
  searchParams: Promise<{
    code?: string;
  }>;
};

export default async function TenantSsoPage({ params, searchParams }: TenantSsoPageProps) {
  const { orgSlug, tenantSlug } = await params;
  const { code } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <SsoCompletion code={code ?? ''} context={{ orgSlug, tenantSlug }} />
    </AuthLayout>
  );
}
