import Image from 'next/image';
import { getTranslations } from 'next-intl/server';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Link } from '@/components/ui/Link';
import deletedTenantImage from '@/assets/deleted-tenant.svg';
import { TenantDeletedCookieConsumer } from './tenant-deleted-cookie-consumer';

type TenantDeletededPageProps = {
  searchParams: Promise<{ org?: string; tenant?: string }>;
};

export default async function TenantDeletedPage({ searchParams }: TenantDeletededPageProps) {
  const { org, tenant } = await searchParams;
  const t = await getTranslations('auth.statusPages');
  const tPage = await getTranslations('auth.statusPages.tenantDeleted');
  const loginHref =
    org && tenant
      ? `/organizations/${encodeURIComponent(org)}/tenants/${encodeURIComponent(tenant)}/login`
      : '/login';

  return (
    <AuthLayout showFooter skipAuthenticatedRedirect>
      <TenantDeletedCookieConsumer />
      <AuthCard
        title={tPage('title')}
        subtitle={tPage('subtitle')}
        backToLogin={false}
        icon={
          <Image
            src={deletedTenantImage}
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
            <ul className="mt-1 list-disc space-y-0.5 pl-4">
              <li>{tPage('items.dataDeleted')}</li>
              <li>{tPage('items.accountDeleted')}</li>
              <li>{tPage('items.irreversible')}</li>
            </ul>
          </div>
        </div>

        <p className="mt-4 text-center text-sm font-semibold text-primary">{t('thanks')}</p>

        <div className="-mx-4 mt-4 flex items-center justify-center border-t border-borderGray px-4 pt-6">
          <Link
            href={loginHref}
            variant="outline"
            className="h-10 w-full justify-center text-white text-sm font-medium tracking-normal border-borderGray hover:bg-hoverBg"
          >
            {t('returnToLogin')}
          </Link>
        </div>
      </AuthCard>
    </AuthLayout>
  );
}
