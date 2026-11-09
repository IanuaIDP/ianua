import { apiClient } from '@/lib/api/client';
import { buildSortParam, getList } from '@/lib/api/crud';
import { formatBackendDate } from '@/utils/date';
import type { DataClassLevel } from '@/types/classification';
import type {
  ResourceAction,
  ResourceType,
  ResourceTypeList,
  ResourceTypeSortDirection,
  ResourceTypeSortField,
} from '@/types/resource-type';

type ResourceActionResponse = {
  display_name?: string | null;
  grants?: string[] | null;
  implies?: string[] | null;
  key?: string | null;
};

type ResourceTypeResponse = {
  actions?: ResourceActionResponse[] | null;
  created_at?: string | null;
  data_class?: DataClassLevel | null;
  description?: string | null;
  display_name?: string | null;
  id: string;
  key?: string | null;
  updated_at?: string | null;
};

type ResourceTypeListResponse = {
  items: ResourceTypeResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetResourceTypesParams = {
  after?: string;
  limit?: number;
  sortDirection?: ResourceTypeSortDirection;
  sortField?: ResourceTypeSortField;
};

/// What a form supplies to declare or update a resource type.
export type ResourceTypePayload = {
  actions: { displayName: string; implies: string[]; key: string }[];
  dataClass: DataClassLevel;
  description: string;
  displayName: string;
  key: string;
};

function endpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/resource-types`;
}

function toAction(response: ResourceActionResponse): ResourceAction {
  return {
    displayName: response.display_name || response.key || '',
    grants: response.grants ?? [],
    implies: response.implies ?? [],
    key: response.key ?? '',
  };
}

function toResourceType(response: ResourceTypeResponse): ResourceType {
  return {
    actions: (response.actions ?? []).map(toAction),
    created: formatBackendDate(response.created_at),
    dataClass: response.data_class ?? 'Internal',
    description: response.description ?? null,
    displayName: response.display_name || response.key || 'Untitled',
    id: response.id,
    key: response.key ?? '',
  };
}

/// The update body carries no key: it is what every role and route already
/// refers to, so the API refuses to change it in place.
function toUpdateRequest(payload: ResourceTypePayload) {
  return {
    actions: payload.actions.map((action) => ({
      display_name: action.displayName.trim(),
      implies: action.implies,
      key: action.key.trim(),
    })),
    data_class: payload.dataClass,
    description: payload.description.trim() || null,
    display_name: payload.displayName.trim(),
  };
}

export async function getTenantResourceTypes(
  orgSlug: string,
  tenantSlug: string,
  params?: GetResourceTypesParams,
): Promise<ResourceTypeList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<ResourceTypeListResponse>(endpoint(orgSlug, tenantSlug), {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
    },
  });

  return {
    items: response.items.map(toResourceType),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function declareTenantResourceType(
  orgSlug: string,
  tenantSlug: string,
  payload: ResourceTypePayload,
): Promise<string> {
  const { data } = await apiClient.post<{ id: string }>(endpoint(orgSlug, tenantSlug), {
    ...toUpdateRequest(payload),
    key: payload.key.trim(),
  });

  return data.id;
}

export async function updateTenantResourceType(
  orgSlug: string,
  tenantSlug: string,
  id: string,
  payload: ResourceTypePayload,
): Promise<void> {
  await apiClient.patch(
    `${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`,
    toUpdateRequest(payload),
  );
}

export async function deleteTenantResourceType(
  orgSlug: string,
  tenantSlug: string,
  id: string,
): Promise<void> {
  await apiClient.delete(`${endpoint(orgSlug, tenantSlug)}/${encodeURIComponent(id)}`);
}
