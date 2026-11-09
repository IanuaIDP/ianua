import { AuthLayout } from '@/components/auth/AuthLayout';
import { TenantSignUpForm } from '@/components/auth/tenant-sign-up-form';

type TenantSignUpPageProps = {
  params: Promise<{
    orgSlug: string;
    tenantSlug: string;
  }>;
};

export default async function TenantSignUpPage({ params }: TenantSignUpPageProps) {
  const { orgSlug, tenantSlug } = await params;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <TenantSignUpForm context={{ orgSlug, tenantSlug }} />
    </AuthLayout>
  );
}
