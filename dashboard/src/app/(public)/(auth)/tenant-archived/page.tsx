import Image from 'next/image';
import { getTranslations } from 'next-intl/server';

import { AuthCard } from '@/components/auth/AuthCard';
import { AuthLayout } from '@/components/auth/AuthLayout';
import { Link } from '@/components/ui/Link';
import archivedTenantImage from '@/assets/archived-tenant.svg';
import { TenantArchivedCookieConsumer } from './tenant-archived-cookie-consumer';

type TenantArchivedPageProps = {
  searchParams: Promise<{ org?: string; tenant?: string }>;
};

export default async function TenantArchivedPage({ searchParams }: TenantArchivedPageProps) {
  const { org, tenant } = await searchParams;
  const t = await getTranslations('auth.statusPages');
  const tPage = await getTranslations('auth.statusPages.tenantArchived');
  const loginHref =
    org && tenant
      ? `/organizations/${encodeURIComponent(org)}/tenants/${encodeURIComponent(tenant)}/login`
      : '/login';

  return (
    <AuthLayout showFooter skipAuthenticatedRedirect>
      <TenantArchivedCookieConsumer />
      <AuthCard
        title={tPage('title')}
        subtitle={tPage('subtitle')}
        backToLogin={false}
        icon={
          <Image
            src={archivedTenantImage}
            alt={tPage('imageAlt')}
            className="pointer-events-none h-auto w-full max-w-80 select-none"
            priority
          />
        }
        width="w-full max-w-103"
        className="px-4!"
      >
        <div className="-mx-4 mt-2 border-t border-borderGray p-2.5">
          <p className="mt-4 text-center text-sm font-semibold text-primary">{t('thanks')}</p>

          <div className="mt-4 flex items-center justify-center gap-3">
            <Link
              href={loginHref}
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
        </div>
      </AuthCard>
    </AuthLayout>
  );
}
