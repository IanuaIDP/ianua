import { AuthLayout } from '@/components/auth/AuthLayout';
import { LoginForm } from '@/components/auth/login-form';
import { getSafeDashboardPath } from '@/lib/auth/sign-in-return';

type LoginPageProps = {
  searchParams: Promise<{ next?: string }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const { next } = await searchParams;
  const nextPath = getSafeDashboardPath(next);

  return (
    <AuthLayout showFooter skipAuthenticatedRedirect={Boolean(nextPath)}>
      <LoginForm nextPath={nextPath} />
    </AuthLayout>
  );
}
