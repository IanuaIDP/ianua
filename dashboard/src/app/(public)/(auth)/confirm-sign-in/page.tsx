import { AuthLayout } from '@/components/auth/AuthLayout';
import { SignInConfirmation } from '@/components/auth/sign-in-confirmation';

type ConfirmSignInPageProps = {
  searchParams: Promise<{
    org?: string;
    tenant?: string;
    token?: string;
  }>;
};

export default async function ConfirmSignInPage({ searchParams }: ConfirmSignInPageProps) {
  const { org, tenant, token } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <SignInConfirmation orgSlug={org ?? ''} tenantSlug={tenant ?? ''} token={token ?? ''} />
    </AuthLayout>
  );
}
