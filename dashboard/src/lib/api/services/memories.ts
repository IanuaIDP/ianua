import { apiClient } from '@/lib/api/client';
import type { CreateMemoryInput, Memory, MemoryEntryPage } from '@/types/memory';

type MemoryResponse = {
  clearance: string;
  created_at: string;
  created_by: string;
  deleted_after?: string | null;
  embedding_model: string;
  embedding_source: string;
  id: string;
  name: string;
  provider_id?: string | null;
  status: string;
  updated_at: string;
  vector_size: number;
};

type MemoryEntryPageResponse = {
  entries: { exposure: string; id: string; kept_at: string; text: string }[];
  next?: string | null;
};

function getMemoriesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/memories`;
}

function getMemoryEndpoint(orgSlug: string, tenantSlug: string, memoryId: string) {
  return `${getMemoriesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(memoryId)}`;
}

function toMemory(response: MemoryResponse): Memory {
  return {
    clearance: response.clearance.toLowerCase(),
    createdAt: response.created_at,
    createdBy: response.created_by,
    deletedAfter: response.deleted_after ?? null,
    embeddingModel: response.embedding_model,
    embeddingSource: response.embedding_source,
    id: response.id,
    name: response.name,
    providerId: response.provider_id ?? null,
    status: response.status,
    updatedAt: response.updated_at,
    vectorSize: response.vector_size,
  };
}

/** Memories spell a clearance with a capital, workflows do not. */
function toApiClearance(clearance: string) {
  return clearance.charAt(0).toUpperCase() + clearance.slice(1);
}

/** The tenant's memories by name, those waiting to be deleted among them. */
export async function getMemories(orgSlug: string, tenantSlug: string): Promise<Memory[]> {
  const { data } = await apiClient.get<MemoryResponse[]>(getMemoriesEndpoint(orgSlug, tenantSlug));

  return data.map(toMemory);
}

/** Makes an empty memory, filled by the platform's embedding server or a provider's model. */
export async function createMemory(
  orgSlug: string,
  tenantSlug: string,
  input: CreateMemoryInput,
): Promise<Memory> {
  const { data } = await apiClient.post<MemoryResponse>(getMemoriesEndpoint(orgSlug, tenantSlug), {
    clearance: toApiClearance(input.clearance),
    name: input.name,
    provider_id: input.providerId,
  });

  return toMemory(data);
}

/** Sets a memory to be deleted. `name` must match its name exactly. */
export async function deleteMemory(
  orgSlug: string,
  tenantSlug: string,
  memoryId: string,
  name: string,
): Promise<Memory> {
  const { data } = await apiClient.post<MemoryResponse>(
    `${getMemoryEndpoint(orgSlug, tenantSlug, memoryId)}/delete`,
    { name },
  );

  return toMemory(data);
}

/** Brings back a memory set to be deleted, with every text it kept. */
export async function restoreMemory(
  orgSlug: string,
  tenantSlug: string,
  memoryId: string,
): Promise<Memory> {
  const { data } = await apiClient.post<MemoryResponse>(
    `${getMemoryEndpoint(orgSlug, tenantSlug, memoryId)}/restore`,
  );

  return toMemory(data);
}

/** One page of a memory's texts, oldest first. */
export async function getMemoryEntries(
  orgSlug: string,
  tenantSlug: string,
  memoryId: string,
  from?: string,
): Promise<MemoryEntryPage> {
  const { data } = await apiClient.get<MemoryEntryPageResponse>(
    `${getMemoryEndpoint(orgSlug, tenantSlug, memoryId)}/entries`,
    { params: { from } },
  );

  return {
    entries: data.entries.map((entry) => ({
      exposure: entry.exposure.toLowerCase(),
      id: entry.id,
      keptAt: entry.kept_at,
      text: entry.text,
    })),
    nextCursor: data.next ?? null,
  };
}
