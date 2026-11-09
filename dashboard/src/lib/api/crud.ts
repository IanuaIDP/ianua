import type { AxiosRequestConfig } from 'axios';

import { apiClient } from '@/lib/api/client';

type ResourceId = number | string;
type QueryParams = Record<string, boolean | number | string | undefined>;

type CrudOptions = {
  config?: AxiosRequestConfig;
  params?: QueryParams;
};

function withId(endpoint: string, id: ResourceId) {
  return `${endpoint.replace(/\/$/, '')}/${id}`;
}

export function buildSortParam<SortField extends string>(
  sortField: SortField | undefined,
  sortDirection: 'asc' | 'desc' | undefined,
): string | undefined {
  if (!sortField || !sortDirection) {
    return undefined;
  }

  return `${sortDirection === 'desc' ? '-' : ''}${sortField}`;
}

export async function getList<TResponse>(endpoint: string, options?: CrudOptions) {
  const response = await apiClient.get<TResponse>(endpoint, {
    ...options?.config,
    params: options?.params,
  });

  return response.data;
}

export async function getById<TResponse>(
  endpoint: string,
  id: ResourceId,
  options?: Omit<CrudOptions, 'params'>,
) {
  const response = await apiClient.get<TResponse>(withId(endpoint, id), options?.config);

  return response.data;
}

export async function createResource<TResponse, TPayload>(
  endpoint: string,
  payload: TPayload,
  options?: Omit<CrudOptions, 'params'>,
) {
  const response = await apiClient.post<TResponse>(endpoint, payload, options?.config);

  return response.data;
}

export async function updateResource<TResponse, TPayload>(
  endpoint: string,
  id: ResourceId,
  payload: TPayload,
  options?: Omit<CrudOptions, 'params'>,
) {
  const response = await apiClient.put<TResponse>(withId(endpoint, id), payload, options?.config);

  return response.data;
}

export async function patchResource<TResponse, TPayload>(
  endpoint: string,
  id: ResourceId,
  payload: TPayload,
  options?: Omit<CrudOptions, 'params'>,
) {
  const response = await apiClient.patch<TResponse>(withId(endpoint, id), payload, options?.config);

  return response.data;
}

export async function deleteResource<TResponse = void>(
  endpoint: string,
  id: ResourceId,
  options?: Omit<CrudOptions, 'params'>,
) {
  const response = await apiClient.delete<TResponse>(withId(endpoint, id), options?.config);

  return response.data;
}

export function createCrudService<TResource, TCreatePayload, TUpdatePayload = Partial<TResource>>(
  endpoint: string,
) {
  return {
    create: (payload: TCreatePayload, config?: AxiosRequestConfig) =>
      createResource<TResource, TCreatePayload>(endpoint, payload, { config }),
    delete: (id: ResourceId, config?: AxiosRequestConfig) =>
      deleteResource<void>(endpoint, id, { config }),
    get: (id: ResourceId, config?: AxiosRequestConfig) =>
      getById<TResource>(endpoint, id, { config }),
    list: (params?: QueryParams, config?: AxiosRequestConfig) =>
      getList<TResource[]>(endpoint, { config, params }),
    patch: (id: ResourceId, payload: Partial<TUpdatePayload>, config?: AxiosRequestConfig) =>
      patchResource<TResource, Partial<TUpdatePayload>>(endpoint, id, payload, { config }),
    update: (id: ResourceId, payload: TUpdatePayload, config?: AxiosRequestConfig) =>
      updateResource<TResource, TUpdatePayload>(endpoint, id, payload, { config }),
  };
}

export type { QueryParams, ResourceId };
