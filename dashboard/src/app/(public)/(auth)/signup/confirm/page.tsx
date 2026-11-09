import { AuthLayout } from '@/components/auth/AuthLayout';
import { SignupConfirmation } from '@/components/auth/signup-confirmation';

type SignupConfirmPageProps = {
  searchParams: Promise<{
    token?: string;
  }>;
};

export default async function SignupConfirmPage({ searchParams }: SignupConfirmPageProps) {
  const { token } = await searchParams;

  return (
    <AuthLayout showBtn={false} showFooter skipAuthenticatedRedirect>
      <SignupConfirmation token={token ?? ''} />
    </AuthLayout>
  );
}
