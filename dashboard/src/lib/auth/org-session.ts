import { getOrgAccess } from '@/lib/api/services/auth';
import { useAuthStore } from '@/store/auth-store';
import type { LoginResponse } from '@/types/auth';

/**
 * Gives an organization sign-in the access it is stored with. The rest of the
 * app reads a stored session with no `access` as a tenant session, so a member
 * is never stored before this returns.
 */
export async function withOrgAccess(
  session: LoginResponse,
  orgSlug: string,
): Promise<LoginResponse> {
  if (session.access) {
    return session;
  }

  useAuthStore.getState().setTokens({ accessToken: session.accessToken });

  const access = await getOrgAccess(orgSlug);
  const tenant = access?.tenants.find((entry) => entry.slug === session.user.tenantSlug);

  return {
    ...session,
    access,
    user: { ...session.user, tenantName: tenant?.displayName ?? session.user.tenantName },
  };
}
