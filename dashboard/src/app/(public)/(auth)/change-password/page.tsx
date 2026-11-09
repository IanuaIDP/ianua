import { AuthLayout } from '@/components/auth/AuthLayout';
import { MailedPasswordChange } from '@/components/auth/mailed-password-change';

type ChangePasswordPageProps = {
  searchParams: Promise<{
    org?: string;
    tenant?: string;
    token?: string;
  }>;
};

export default async function ChangePasswordPage({ searchParams }: ChangePasswordPageProps) {
  const { org, tenant, token } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <MailedPasswordChange orgSlug={org ?? ''} tenantSlug={tenant ?? ''} token={token ?? ''} />
    </AuthLayout>
  );
}
