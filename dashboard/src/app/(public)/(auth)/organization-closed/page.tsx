import Image from 'next/image';
import { useTranslations } from 'next-intl';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Link } from '@/components/ui/Link';
import goodbye from '@/assets/goodbye.svg';
import { OrganizationClosedCookieConsumer } from './organization-closed-cookie-consumer';

export default function OrganizationClosedPage() {
  const t = useTranslations('auth.statusPages');
  const tPage = useTranslations('auth.statusPages.organizationClosed');

  return (
    <AuthLayout showFooter skipAuthenticatedRedirect>
      <OrganizationClosedCookieConsumer />
      <AuthCard
        title={tPage('title')}
        subtitle={tPage('subtitle')}
        backToLogin={false}
        icon={
          <Image
            src={goodbye}
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
            <p className="font-semibold">{t('whatThisMeans')}</p>

            <ul className="list-disc space-y-1 pl-5">
              <li className="m-0">{tPage('items.dataDeleted')}</li>
              <li className="m-0">{tPage('items.accountDeleted')}</li>
              <li className="m-0">{tPage('items.irreversible')}</li>
            </ul>
          </div>
        </div>

        <div className="-mx-4 mt-6 border-t border-borderGray px-4 pt-6 text-center">
          <p className="mb-3 text-xs text-primary ">{t('thanks')}</p>
          <Link
            href="/login"
            variant="outline"
            className="text-white text-sm font-medium tracking-normal border-borderGray hover:bg-hoverBg"
            rightIcon={<span className="material-symbols-rounded">arrow_forward</span>}
          >
            {t('returnToLogin')}
          </Link>
        </div>
      </AuthCard>
    </AuthLayout>
  );
}
