import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import type { AddGroupMemberInput, GroupInput } from '@/schemas/group-schemas';
import type {
  Group,
  GroupList,
  GroupMember,
  GroupMemberKind,
  GroupSortDirection,
  GroupSortField,
} from '@/types/group';
import { formatBackendDate } from '@/utils/date';

type GroupResponse = {
  created_at?: string | null;
  id: string;
  name?: string | null;
  parent_id?: string | null;
  role_ids?: string[] | null;
  updated_at?: string | null;
};

type GroupListResponse = {
  items: GroupResponse[];
  limit: number;
  next_cursor: string | null;
};

type GroupMemberResponse = {
  display_name?: string | null;
  id: string;
  joined_at?: string | null;
  kind: GroupMemberKind;
};

type CreateGroupRequest = {
  name: string;
  parent_id?: string;
};

type AddGroupMemberRequest = {
  id: string;
  kind: GroupMemberKind;
};

type AssignGroupRoleRequest = {
  role_id: string;
};

type GetTenantGroupsParams = {
  after?: string;
  limit?: number;
  sortDirection?: GroupSortDirection;
  sortField?: GroupSortField;
};

function getTenantGroupsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/authorization/groups`;
}

function toGroup(response: GroupResponse): Group {
  const roleIds = response.role_ids ?? [];

  return {
    createdAt: formatBackendDate(response.created_at),
    id: response.id,
    name: response.name || 'Untitled group',
    parentId: response.parent_id ?? undefined,
    roleIds,
    rolesCount: roleIds.length,
    updatedAt: formatBackendDate(response.updated_at),
  };
}

function toGroupMember(response: GroupMemberResponse): GroupMember {
  return {
    displayName: response.display_name || response.id,
    id: response.id,
    joinedAt: formatBackendDate(response.joined_at),
    kind: response.kind,
  };
}

export async function getTenantGroups(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantGroupsParams,
): Promise<GroupList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);
  const response = await getList<GroupListResponse>(getTenantGroupsEndpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toGroup),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function createGroup(orgSlug: string, tenantSlug: string, payload: GroupInput) {
  await apiClient.post(getTenantGroupsEndpoint(orgSlug, tenantSlug), {
    name: payload.name,
    ...(payload.parentId ? { parent_id: payload.parentId } : {}),
  } satisfies CreateGroupRequest);
}

export async function deleteGroup(orgSlug: string, tenantSlug: string, groupId: string) {
  await apiClient.delete(
    `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(groupId)}`,
  );
}

export async function getGroupMembers(
  orgSlug: string,
  tenantSlug: string,
  groupId: string,
): Promise<GroupMember[]> {
  const members: GroupMemberResponse[] = [];
  let after: string | undefined;

  do {
    const page = await getList<{ items: GroupMemberResponse[]; next_cursor: string | null }>(
      `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(groupId)}/members`,
      { params: { after, limit: 100 } },
    );

    members.push(...page.items);
    after = page.next_cursor ?? undefined;
  } while (after);

  return members.map(toGroupMember);
}

/** Renames the group and, when `parentId` changed, moves it. */
export async function updateGroup(
  orgSlug: string,
  tenantSlug: string,
  group: Group,
  payload: GroupInput,
) {
  const endpoint = `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(group.id)}`;

  if (payload.name !== group.name) {
    await apiClient.patch(endpoint, { name: payload.name });
  }

  const parentId = payload.parentId || null;

  if (parentId !== group.parentId) {
    await apiClient.put(`${endpoint}/parent`, { parent_id: parentId });
  }
}

export async function addGroupMember(
  orgSlug: string,
  tenantSlug: string,
  groupId: string,
  payload: AddGroupMemberInput,
) {
  await apiClient.post(
    `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(groupId)}/members`,
    { id: payload.id, kind: payload.kind } satisfies AddGroupMemberRequest,
  );
}

export async function removeGroupMember(
  orgSlug: string,
  tenantSlug: string,
  groupId: string,
  member: Pick<GroupMember, 'id' | 'kind'>,
) {
  await apiClient.delete(
    `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      groupId,
    )}/members/${encodeURIComponent(member.kind)}/${encodeURIComponent(member.id)}`,
  );
}

export async function assignGroupRole(
  orgSlug: string,
  tenantSlug: string,
  groupId: string,
  roleId: string,
) {
  await apiClient.post(
    `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(groupId)}/roles`,
    { role_id: roleId } satisfies AssignGroupRoleRequest,
  );
}

export async function unassignGroupRole(
  orgSlug: string,
  tenantSlug: string,
  groupId: string,
  roleId: string,
) {
  await apiClient.delete(
    `${getTenantGroupsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      groupId,
    )}/roles/${encodeURIComponent(roleId)}`,
  );
}
