import { AuthLayout } from '@/components/auth/AuthLayout';
import { MagicLinkCompletion } from '@/components/auth/magic-link-completion';

type MagicLinkPageProps = {
  searchParams: Promise<{
    org?: string;
    tenant?: string;
    token?: string;
  }>;
};

export default async function MagicLinkPage({ searchParams }: MagicLinkPageProps) {
  const { org, tenant, token } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <MagicLinkCompletion orgSlug={org ?? ''} tenantSlug={tenant ?? ''} token={token ?? ''} />
    </AuthLayout>
  );
}
