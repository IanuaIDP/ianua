import {
  getCurrentTenantUser,
  getOrganizationMe,
  updateCurrentTenantUserLocale,
  updateOrganizationMeLocale,
} from '@/lib/api';
import { toBackendLocale } from '@/i18n/config';
import type { AppLocale } from '@/i18n/config';

export type ProfileSession = {
  isTenantSession: boolean;
  organizationSlug?: string;
  tenantSlug?: string;
};

/**
 * Whose profile to use. An organization login also stores the organization's
 * first tenant in the session, so a tenant slug alone does not make someone a
 * tenant user: only a session without organization `access` is a tenant session.
 */
export function toProfileSession(session: {
  access: unknown;
  organizationSlug?: string;
  tenantSlug?: string;
}): ProfileSession {
  return {
    isTenantSession: session.access === null,
    organizationSlug: session.organizationSlug,
    tenantSlug: session.tenantSlug,
  };
}

export async function getProfileLocale(session: ProfileSession): Promise<string | null> {
  const { isTenantSession, organizationSlug, tenantSlug } = session;

  if (!organizationSlug) {
    return null;
  }

  if (isTenantSession) {
    return tenantSlug ? (await getCurrentTenantUser(organizationSlug, tenantSlug)).locale : null;
  }

  return (await getOrganizationMe(organizationSlug)).locale;
}

export async function saveProfileLocale(session: ProfileSession, locale: AppLocale) {
  const { isTenantSession, organizationSlug, tenantSlug } = session;

  if (!organizationSlug) {
    return;
  }

  if (isTenantSession) {
    if (tenantSlug) {
      await updateCurrentTenantUserLocale(organizationSlug, tenantSlug, toBackendLocale(locale));
    }

    return;
  }

  await updateOrganizationMeLocale(organizationSlug, toBackendLocale(locale));
}
