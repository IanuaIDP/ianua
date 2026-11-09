import { AuthLayout } from '@/components/auth/AuthLayout';
import { LoginForm } from '@/components/auth/login-form';
import { getSafeNextPath } from '@/lib/auth/sign-in-return';
import { getTenantPath } from '@/utils/dashboard-routes';

type TenantLoginPageProps = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
  searchParams: Promise<{
    logout?: string;
    next?: string;
    sso?: string;
  }>;
};

export default async function TenantLoginPage({ params, searchParams }: TenantLoginPageProps) {
  const { orgSlug, tenantSlug } = await params;
  const { logout, next, sso } = await searchParams;
  const tenantPath = getTenantPath(orgSlug, tenantSlug);

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <LoginForm
        forgotPasswordHref={`${tenantPath}/forgot-password`}
        logoutStatus={logout}
        nextPath={getSafeNextPath(next, tenantPath)}
        orgSlug={orgSlug}
        ssoFailed={sso === 'failed'}
        tenantSlug={tenantSlug}
      />
    </AuthLayout>
  );
}
