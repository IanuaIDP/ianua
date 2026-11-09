import { AuthLayout } from '@/components/auth/AuthLayout';
import { OrgSsoCompletion } from '@/components/auth/org-sso-completion';

export default function OrgSsoSamlPage() {
  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <OrgSsoCompletion />
    </AuthLayout>
  );
}
