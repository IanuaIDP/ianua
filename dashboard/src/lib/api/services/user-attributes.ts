import { apiClient } from '@/lib/api/client';
import { toNumber, type UserAttributeInput } from '@/schemas/user-attribute-schemas';
import type {
  UserAttribute,
  UserAttributeControl,
  UserAttributeKind,
  UserAttributeKindOption,
  UserAttributeNamespace,
  UserAttributeOperator,
  UserAttributeValue,
  UserAttributeValues,
} from '@/types/user-attribute';
import { formatBackendDate } from '@/utils/date';

type UserAttributeResponse = {
  archived?: boolean | null;
  available_controls?: UserAttributeControl[] | null;
  control: UserAttributeControl;
  created_at?: string | null;
  description?: string | null;
  display_name?: string | null;
  filterable?: boolean | null;
  key: string;
  kind: UserAttributeKind;
  listed?: boolean | null;
  max_length?: number | null;
  maximum?: number | null;
  minimum?: number | null;
  namespace: UserAttributeNamespace;
  operators?: UserAttributeOperator[] | null;
  options?: string[] | null;
  required?: boolean | null;
  sensitive?: boolean | null;
  sortable?: boolean | null;
  updated_at?: string | null;
};

type UserAttributeKindResponse = {
  available_controls?: UserAttributeControl[] | null;
  default_control: UserAttributeControl;
  kind: UserAttributeKind;
  operators?: UserAttributeOperator[] | null;
  requires_options?: boolean | null;
  sortable?: boolean | null;
  supports_max_length?: boolean | null;
  supports_range?: boolean | null;
};

type UserAttributeValuesResponse = {
  values?: UserAttributeValues | null;
};

type DeclareUserAttributeRequest = {
  control?: UserAttributeControl;
  description?: string;
  display_name: string;
  filterable: boolean;
  key?: string;
  kind: UserAttributeKind;
  listed: boolean;
  max_length?: number;
  maximum?: number;
  minimum?: number;
  namespace: UserAttributeNamespace;
  options: string[];
  required: boolean;
  sensitive: boolean;
  sortable: boolean;
};

function getUserAttributesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/user-attributes`;
}

function getUserValuesEndpoint(orgSlug: string, tenantSlug: string, userId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/users/${encodeURIComponent(userId)}/attributes`;
}

function toUserAttribute(response: UserAttributeResponse): UserAttribute {
  return {
    archived: Boolean(response.archived),
    availableControls: response.available_controls ?? [response.control],
    control: response.control,
    createdAt: formatBackendDate(response.created_at),
    description: response.description ?? undefined,
    displayName: response.display_name || response.key,
    filterable: Boolean(response.filterable),
    key: response.key,
    kind: response.kind,
    listed: Boolean(response.listed),
    maxLength: response.max_length ?? undefined,
    maximum: response.maximum ?? undefined,
    minimum: response.minimum ?? undefined,
    namespace: response.namespace,
    operators: response.operators ?? [],
    options: response.options ?? [],
    required: Boolean(response.required),
    sensitive: Boolean(response.sensitive),
    sortable: Boolean(response.sortable),
    updatedAt: formatBackendDate(response.updated_at),
  };
}

function toUserAttributeKindOption(response: UserAttributeKindResponse): UserAttributeKindOption {
  return {
    availableControls: response.available_controls ?? [response.default_control],
    defaultControl: response.default_control,
    kind: response.kind,
    operators: response.operators ?? [],
    requiresOptions: Boolean(response.requires_options),
    sortable: Boolean(response.sortable),
    supportsMaxLength: Boolean(response.supports_max_length),
    supportsRange: Boolean(response.supports_range),
  };
}

function toDeclareRequest(payload: UserAttributeInput): DeclareUserAttributeRequest {
  const options = payload.options.map((option) => option.trim()).filter(Boolean);
  const maxLength = toNumber(payload.maxLength);
  const minimum = toNumber(payload.minimum);
  const maximum = toNumber(payload.maximum);
  const description = payload.description.trim();
  const key = payload.key.trim();

  return {
    ...(payload.control ? { control: payload.control as UserAttributeControl } : {}),
    ...(description ? { description } : {}),
    display_name: payload.displayName.trim(),
    filterable: payload.filterable,
    ...(key ? { key } : {}),
    kind: payload.kind as UserAttributeKind,
    listed: payload.listed,
    ...(maxLength === undefined ? {} : { max_length: maxLength }),
    ...(maximum === undefined ? {} : { maximum }),
    ...(minimum === undefined ? {} : { minimum }),
    namespace: payload.namespace,
    options,
    required: payload.required,
    sensitive: payload.sensitive,
    sortable: payload.sortable,
  };
}

export async function getUserAttributeKinds(
  orgSlug: string,
  tenantSlug: string,
): Promise<UserAttributeKindOption[]> {
  const response = await apiClient.get<UserAttributeKindResponse[]>(
    `${getUserAttributesEndpoint(orgSlug, tenantSlug)}/kinds`,
  );

  return (response.data ?? []).map(toUserAttributeKindOption);
}

export async function getUserAttributes(
  orgSlug: string,
  tenantSlug: string,
  params?: { includeArchived?: boolean },
): Promise<UserAttribute[]> {
  const response = await apiClient.get<UserAttributeResponse[]>(
    getUserAttributesEndpoint(orgSlug, tenantSlug),
    { params: { include_archived: params?.includeArchived ? true : undefined } },
  );

  return (response.data ?? []).map(toUserAttribute);
}

export async function declareUserAttribute(
  orgSlug: string,
  tenantSlug: string,
  payload: UserAttributeInput,
) {
  await apiClient.post(
    getUserAttributesEndpoint(orgSlug, tenantSlug),
    toDeclareRequest(payload) satisfies DeclareUserAttributeRequest,
  );
}

export async function updateUserAttribute(
  orgSlug: string,
  tenantSlug: string,
  attribute: Pick<UserAttribute, 'key' | 'namespace'>,
  payload: UserAttributeInput,
) {
  const request = toDeclareRequest(payload);

  // The internal name and the kind are fixed once declared, so a change never
  // sends them. Everything else is sent whole, which is also how the form
  // reads: it starts from the current declaration.
  await apiClient.patch(
    `${getUserAttributesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      attribute.namespace,
    )}/${encodeURIComponent(attribute.key)}`,
    {
      control: request.control,
      description: request.description ?? null,
      display_name: request.display_name,
      filterable: request.filterable,
      listed: request.listed,
      max_length: request.max_length ?? null,
      maximum: request.maximum ?? null,
      minimum: request.minimum ?? null,
      ...(request.options.length > 0 ? { options: request.options } : {}),
      required: request.required,
      sensitive: request.sensitive,
      sortable: request.sortable,
    },
  );
}

export async function setUserAttributeArchived(
  orgSlug: string,
  tenantSlug: string,
  attribute: Pick<UserAttribute, 'key' | 'namespace'>,
  archived: boolean,
) {
  await apiClient.put(
    `${getUserAttributesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      attribute.namespace,
    )}/${encodeURIComponent(attribute.key)}/status`,
    { archived },
  );
}

export async function deleteUserAttribute(
  orgSlug: string,
  tenantSlug: string,
  attribute: Pick<UserAttribute, 'key' | 'namespace'>,
): Promise<number> {
  const response = await apiClient.delete<{ values_discarded?: number | null }>(
    `${getUserAttributesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(
      attribute.namespace,
    )}/${encodeURIComponent(attribute.key)}`,
  );

  return response.data?.values_discarded ?? 0;
}

export async function getUserAttributeValues(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
): Promise<UserAttributeValues> {
  const response = await apiClient.get<UserAttributeValuesResponse>(
    getUserValuesEndpoint(orgSlug, tenantSlug, userId),
  );

  return response.data?.values ?? {};
}

export async function setUserAttributeValue(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
  attribute: Pick<UserAttribute, 'key' | 'namespace'>,
  value: UserAttributeValue,
) {
  await apiClient.put(
    `${getUserValuesEndpoint(orgSlug, tenantSlug, userId)}/${encodeURIComponent(
      attribute.namespace,
    )}/${encodeURIComponent(attribute.key)}`,
    { value },
  );
}
