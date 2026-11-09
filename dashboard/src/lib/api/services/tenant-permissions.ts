import { apiClient } from '@/lib/api/client';
import { toPasswordBreach, type PasswordBreachResponse } from '@/lib/api/services/auth';
import type { AccountSettingsPasswordInput } from '@/schemas/settings-schemas';
import type { PasswordBreach } from '@/types/auth';
import type {
  PermissionValue,
  TenantPermissionAction,
  TenantPermissionResource,
} from '@/types/permission';

type CurrentTenantUserRoleResponse = {
  id: string;
  name: string;
};

type CurrentTenantUserResponse = {
  custom_permissions?: PermissionValue[] | null;
  display_name: string;
  email: string;
  id: string;
  locale?: string | null;
  permissions?: PermissionValue[] | null;
  roles?: CurrentTenantUserRoleResponse[] | null;
};

export type CurrentTenantUser = {
  email: string;
  id: string;
  /** Preferred language tag, or `null` when the user inherits the tenant default. */
  locale: string | null;
  name: string;
  permissionSet: Set<string>;
  roleIds: string[];
};

type UpdateTenantUserLocaleRequest = {
  locale: string;
};

type ChangeTenantPasswordResponse = {
  password_breach: PasswordBreachResponse;
};

type ChangeTenantPasswordRequest = {
  new_password: string;
  old_password: string;
};

function buildPermissionSet(permissions: PermissionValue[]): Set<string> {
  const permissionSet = new Set<string>();

  for (const entry of permissions) {
    for (const [resource, action] of Object.entries(entry)) {
      permissionSet.add(`${resource}:${action}`);
    }
  }

  return permissionSet;
}

function toCurrentTenantUser(response: CurrentTenantUserResponse): CurrentTenantUser {
  return {
    email: response.email,
    id: response.id,
    locale: response.locale ?? null,
    name: response.display_name,
    permissionSet: buildPermissionSet(response.permissions ?? []),
    roleIds: (response.roles ?? []).map((role) => role.id),
  };
}

function getTenantBaseEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}`;
}

function getTenantMeEndpoint(orgSlug: string, tenantSlug: string) {
  return `${getTenantBaseEndpoint(orgSlug, tenantSlug)}/me`;
}

function getTenantAuthEndpoint(orgSlug: string, tenantSlug: string, actionPath: string) {
  return `${getTenantBaseEndpoint(orgSlug, tenantSlug)}/auth/${actionPath}`;
}

export async function getCurrentTenantUser(
  orgSlug: string,
  tenantSlug: string,
): Promise<CurrentTenantUser> {
  const response = await apiClient.get<CurrentTenantUserResponse>(
    getTenantMeEndpoint(orgSlug, tenantSlug),
  );

  return toCurrentTenantUser(response.data);
}

/** Saves only the signed-in tenant user's preferred language (BCP 47 tag, e.g. `uk-UA`). */
export async function updateCurrentTenantUserLocale(
  orgSlug: string,
  tenantSlug: string,
  locale: string,
): Promise<void> {
  await apiClient.patch<unknown>(getTenantMeEndpoint(orgSlug, tenantSlug), {
    locale,
  } satisfies UpdateTenantUserLocaleRequest);
}

export async function changeTenantPassword(
  orgSlug: string,
  tenantSlug: string,
  payload: AccountSettingsPasswordInput,
): Promise<PasswordBreach> {
  const response = await apiClient.post<ChangeTenantPasswordResponse>(
    getTenantAuthEndpoint(orgSlug, tenantSlug, 'password/change'),
    {
      new_password: payload.newPassword,
      old_password: payload.currentPassword,
    } satisfies ChangeTenantPasswordRequest,
  );

  return toPasswordBreach(response.data.password_breach);
}

export function hasTenantPermission(
  permissions: Set<string>,
  resource: TenantPermissionResource,
  action: TenantPermissionAction,
): boolean {
  return permissions.has(`${resource}:${action}`) || permissions.has(`${resource}:Manage`);
}

export function hasAnyTenantPermission(
  permissions: Set<string>,
  resource: TenantPermissionResource,
): boolean {
  const prefix = `${resource}:`;

  for (const permission of permissions) {
    if (permission.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}
