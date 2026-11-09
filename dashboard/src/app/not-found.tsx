'use client';

import Image from 'next/image';
import { usePathname } from 'next/navigation';

import notFoundBackground from '@/assets/404.svg';
import logo from '@/assets/logo.svg';
import { Link } from '@/components/ui/Link';
import { getTenantPath } from '@/utils/dashboard-routes';
import { useAuthStore } from '@/store/auth-store';
import { getTenantRouteContext } from '@/utils/dashboard-routes';

export default function NotFound() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isHydrated = useAuthStore((state) => state.isHydrated);
  const pathname = usePathname();

  if (!isHydrated) {
    return null;
  }

  const routeTenantContext = getTenantRouteContext(pathname);
  const overviewHref = routeTenantContext
    ? `${getTenantPath(routeTenantContext.orgSlug, routeTenantContext.tenantSlug)}/overview`
    : '/overview';

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-appBg px-6 text-center text-white">
      <Image
        src={notFoundBackground}
        alt=""
        fill
        priority
        aria-hidden="true"
        className="pointer-events-none select-none object-cover"
      />

      <Image
        src={logo}
        alt="ianua.io"
        width={100}
        height={34}
        priority
        className="absolute top-3 left-1/2 z-10 -translate-x-1/2 object-contain"
      />

      <div className="relative z-10 flex flex-col items-center">
        <p className="text-[200px] font-extrabold leading-none text-focus drop-shadow-focus-text-glow sm:text-[120px]">
          404
        </p>
        <h1 className="mt-8 text-lg font-bold text-white sm:text-2xl">
          Access denied... to a page that doesn&apos;t exist.
        </h1>
        <p className="mt-2.5 text-sm text-textGray sm:text-lg">
          This page doesn&apos;t exist, or the path has changed.
        </p>

        {isAuthenticated ? (
          <Link
            href={overviewHref}
            leftIcon={<span className="material-symbols-rounded text-base">dashboard</span>}
            className="mt-8 gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold tracking-normal text-black hover:bg-btnWithBgHover hover:text-black"
          >
            Go to Overview
          </Link>
        ) : (
          <Link
            href="/"
            rightIcon={<span className="material-symbols-rounded text-base">arrow_forward</span>}
            className="mt-8 gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-semibold tracking-normal text-black hover:bg-btnWithBgHover hover:text-black"
          >
            Go to Home
          </Link>
        )}
      </div>
    </div>
  );
}
