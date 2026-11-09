import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import { splitPermissions } from '@/lib/roles/catalogue';
import type { CreateRoleInput } from '@/schemas/role-schemas';
import type { ResourceType } from '@/types/resource-type';
import type {
  Role,
  RoleList,
  RolePermission,
  RoleSortDirection,
  RoleSortField,
} from '@/types/role';
import type { Permission, PermissionGroup, PermissionValue } from '@/types/permission';
import { formatBackendDate } from '@/utils/date';

type RolePermissionResponse = {
  action: string;
  resource: string;
};

type RoleResponse = {
  assigned_user_count?: number | null;
  created_at?: string | null;
  custom_permissions?: RolePermissionResponse[] | null;
  id: string;
  is_default?: boolean | null;
  name?: string | null;
  system_permissions?: Record<string, string>[] | null;
  updated_at?: string | null;
};

type RoleListResponse = {
  items: RoleResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantRolesParams = {
  after?: string;
  limit?: number;
  sortDirection?: RoleSortDirection;
  sortField?: RoleSortField;
};

type PermissionResponse = {
  label: string;
  value: PermissionValue;
};

type PermissionGroupResponse = {
  label: string;
  permissions: PermissionResponse[];
};

type CreateRoleRequest = {
  custom_permissions: RolePermissionResponse[];
  is_default: boolean;
  name: string;
  system_permissions: PermissionValue[];
};

function toRolePermission(response: RolePermissionResponse): RolePermission {
  return {
    action: response.action,
    resource: response.resource,
  };
}

function toPermission(response: PermissionResponse): Permission {
  return {
    label: response.label,
    value: response.value,
  };
}

function toPermissionGroup(response: PermissionGroupResponse): PermissionGroup {
  return {
    label: response.label,
    permissions: response.permissions.map(toPermission),
  };
}

function toRole(response: RoleResponse): Role {
  const customPermissions = (response.custom_permissions ?? []).map(toRolePermission);
  const systemPermissions = response.system_permissions ?? [];

  return {
    assignedUserCount: response.assigned_user_count ?? 0,
    createdAt: formatBackendDate(response.created_at),
    customPermissions,
    id: response.id,
    isDefault: Boolean(response.is_default),
    name: response.name || 'Untitled role',
    permissionsCount: customPermissions.length + systemPermissions.length,
    systemPermissions,
  };
}

function getTenantRolesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/authorization/roles`;
}

export async function getTenantRoles(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantRolesParams,
): Promise<RoleList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<RoleListResponse>(getTenantRolesEndpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toRole),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function getTenantPermissions(
  orgSlug: string,
  tenantSlug: string,
): Promise<PermissionGroup[]> {
  const response = await getList<PermissionGroupResponse[]>(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
      tenantSlug,
    )}/authorization/permissions`,
  );

  return response.map(toPermissionGroup);
}

export async function getOrgPermissions(orgSlug: string): Promise<PermissionGroup[]> {
  const response = await getList<PermissionGroupResponse[]>(
    `/organizations/${encodeURIComponent(orgSlug)}/permissions`,
  );

  return response.map(toPermissionGroup);
}

export async function createRole(
  orgSlug: string,
  tenantSlug: string,
  payload: CreateRoleInput,
  resourceTypes: ResourceType[] = [],
): Promise<void> {
  const { custom, system } = splitPermissions(payload.permissions, resourceTypes);

  await createResource<unknown, CreateRoleRequest>(getTenantRolesEndpoint(orgSlug, tenantSlug), {
    custom_permissions: custom,
    is_default: false,
    name: payload.name,
    system_permissions: system,
  });
}

export async function updateRole(
  orgSlug: string,
  tenantSlug: string,
  roleId: string,
  payload: CreateRoleInput,
  isDefault: boolean,
  resourceTypes: ResourceType[] = [],
): Promise<void> {
  const { custom, system } = splitPermissions(payload.permissions, resourceTypes);

  await apiClient.patch(
    `${getTenantRolesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(roleId)}`,
    {
      custom_permissions: custom,
      is_default: isDefault,
      name: payload.name,
      system_permissions: system,
    } satisfies CreateRoleRequest,
  );
}

type DeleteRoleRequest = {
  replacement_role_id: string | null;
};

export async function deleteRole(
  orgSlug: string,
  tenantSlug: string,
  roleId: string,
  reassignToRoleId?: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantRolesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(roleId)}`,
    {
      data: {
        replacement_role_id: reassignToRoleId ?? null,
      } satisfies DeleteRoleRequest,
    },
  );
}

type AssignRoleRequest = {
  user_id: string;
};

export async function assignTenantRole(
  orgSlug: string,
  tenantSlug: string,
  roleId: string,
  userId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantRolesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(roleId)}/assignments`,
    { user_id: userId } satisfies AssignRoleRequest,
  );
}

export async function unassignTenantRole(
  orgSlug: string,
  tenantSlug: string,
  roleId: string,
  userId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantRolesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(roleId)}/assignments/${encodeURIComponent(userId)}`,
  );
}
