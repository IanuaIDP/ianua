import { AuthLayout } from '@/components/auth/AuthLayout';
import { OrgSsoCompletion } from '@/components/auth/org-sso-completion';

type PageProps = {
  searchParams: Promise<{ code?: string; state?: string }>;
};

export default async function OrgSsoOidcPage({ searchParams }: PageProps) {
  const { code, state } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <OrgSsoCompletion oidcAnswer={{ code: code ?? '', state: state ?? '' }} />
    </AuthLayout>
  );
}
