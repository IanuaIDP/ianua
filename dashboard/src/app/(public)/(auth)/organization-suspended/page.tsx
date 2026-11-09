import Image from 'next/image';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Link } from '@/components/ui/Link';
import suspendOrganizationImage from '@/assets/suspend-organization.svg';
import { OrganizationSuspendedCookieConsumer } from './organization-suspended-cookie-consumer';

export default function OrganizationSuspendedPage() {
  const t = useTranslations('auth.statusPages');
  const tPage = useTranslations('auth.statusPages.organizationSuspended');

  return (
    <AuthLayout showFooter skipAuthenticatedRedirect>
      <OrganizationSuspendedCookieConsumer />
      <AuthCard
        title={tPage('title')}
        subtitle={tPage('subtitle')}
        backToLogin={false}
        icon={
          <Image
            src={suspendOrganizationImage}
            alt={tPage('imageAlt')}
            className="pointer-events-none h-auto w-full max-w-80 select-none"
            priority
          />
        }
        width="w-full max-w-103"
        className="px-4!"
      >
        <div className="flex gap-2 mt-2 rounded-lg border border-focus/50 bg-focus/10 p-2.5 text-[10px] font-medium text-focus">
          <span className="material-symbols-rounded">info</span>
          <div className="mt-1">
            <p className="font-semibold">{tPage('needTitle')}</p>
            <p className="mt-1">{tPage('needBody')}</p>
          </div>
        </div>

        <div className="-mx-4 mt-6 flex items-center justify-center gap-3 border-t border-borderGray px-4 pt-6">
          <Link
            href="/login"
            variant="outline"
            className="h-10 flex-1 justify-center text-white text-sm font-medium tracking-normal border-borderGray hover:bg-hoverBg"
          >
            {t('returnToLogin')}
          </Link>
          <button
            type="button"
            className="inline-flex h-10 flex-1 items-center justify-center gap-1.5 rounded-lg bg-focus px-4 text-sm font-medium tracking-normal text-white transition hover:bg-hoverBgPurple"
          >
            {t('contactSupport')}
            <span className="material-symbols-rounded text-base!">open_in_new</span>
          </button>
        </div>
      </AuthCard>
    </AuthLayout>
  );
}
