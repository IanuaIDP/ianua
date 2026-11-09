import { getTenantPath } from '@/utils/dashboard-routes';

/** The tenant sign-in page, set to come back to the page the person is on. */
export function getSignInReturnHref(orgSlug: string, tenantSlug: string) {
  const here = `${window.location.pathname}${window.location.search}`;

  return `${getTenantPath(orgSlug, tenantSlug)}/login?next=${encodeURIComponent(here)}`;
}

/** Where a page sends a signed-out person, set to come back to that page afterwards. */
export function withSignInReturn(loginPath: string, pathname: string, search: string) {
  return `${loginPath}?next=${encodeURIComponent(`${pathname}${search}`)}`;
}

/**
 * The page to come back to after signing in at the organization sign-in: only
 * a path inside the dashboard, since `next` arrives from the address.
 */
export function getSafeDashboardPath(next: string | undefined) {
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.includes('\\')) {
    return undefined;
  }

  return next;
}

/**
 * The page to come back to after signing in, only when it is inside this
 * tenant: `next` arrives from the address, so nothing else is trusted.
 */
export function getSafeNextPath(next: string | undefined, tenantPath: string) {
  if (!next || !next.startsWith(`${tenantPath}/`) || next.includes('//') || next.includes('\\')) {
    return undefined;
  }

  return next;
}
