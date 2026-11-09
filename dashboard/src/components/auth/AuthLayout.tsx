'use client';

import { ReactNode, useEffect } from 'react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';
import logo from '@/assets/logo.svg';
import { FooterLegalBar } from '@/components/landing/footer/footer-legal-bar';
import { LanguageSwitcher } from '@/components/ui/language-switcher';
import { Link } from '@/components/ui/Link';
import { useSignupOpen } from '@/hooks/auth/use-signup-open';
import { useAuthStore } from '@/store/auth-store';

type AuthLayoutProps = {
  children: ReactNode;
  showSignIn?: boolean;
  showBtn?: boolean;
  showFooter?: boolean;
  skipAuthenticatedRedirect?: boolean;
};

export function AuthLayout({
  children,
  showSignIn = false,
  showBtn = true,
  showFooter = false,
  skipAuthenticatedRedirect = false,
}: AuthLayoutProps) {
  const t = useTranslations('auth.layout');
  const tCommon = useTranslations('common');
  const router = useRouter();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const isSignupOpen = useSignupOpen();

  useEffect(() => {
    if (!skipAuthenticatedRedirect && isHydrated && isAuthenticated) {
      router.replace('/overview');
    }
  }, [isAuthenticated, isHydrated, router, skipAuthenticatedRedirect]);

  if (!isHydrated || (!skipAuthenticatedRedirect && isAuthenticated)) {
    return null;
  }

  return (
    <div className="min-h-screen bg-appBg text-white flex flex-col">
      <div className="flex justify-between items-center px-8 pt-4 absolute top-0 left-0 right-0 z-10">
        <Link href="/" className="flex items-center justify-center" aria-label={t('homeAriaLabel')}>
          <Image
            src={logo}
            alt="ianua.io"
            width={100}
            height={34}
            priority
            className="object-contain"
          />
        </Link>
        <div className="flex items-center gap-4">
          <LanguageSwitcher />
          {showBtn && showSignIn ? (
            <Link href="/login" variant="outline">
              {tCommon('signIn')}
            </Link>
          ) : null}
          {showBtn && !showSignIn && isSignupOpen ? (
            <Link href="/sign-up" variant="outline">
              {tCommon('signUp')}
            </Link>
          ) : null}
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center px-6 py-4">{children}</div>

      {showFooter && <FooterLegalBar />}
    </div>
  );
}
