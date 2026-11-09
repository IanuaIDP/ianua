import { apiClient } from '@/lib/api/client';
import { createResource, deleteResource, getList, patchResource } from '@/lib/api/crud';
import type { ConnectModelProviderInput } from '@/schemas/model-provider-schemas';
import type {
  ModelProvider,
  ModelProviderAction,
  ModelProviderKind,
  ModelProviderStatus,
  ModelProviderTestResult,
} from '@/types/model-provider';
import { parseBackendTimestamp } from '@/utils/date';

type ModelProviderResponse = {
  endpoint: string;
  has_credential: boolean;
  id: string;
  kind: string;
  last_test_message?: string | null;
  last_test_status?: string | null;
  last_tested_at?: string | null;
  model: string;
  name: string;
  clearance?: string | null;
  embedding_model?: string | null;
  pricing?: { input_micros_per_million: number; output_micros_per_million: number } | null;
  status: string;
};

type ConnectModelProviderResponse = {
  id: string;
};

type ConnectModelProviderRequest = {
  api_key?: string | null;
  endpoint: string;
  kind: string;
  model: string;
  name: string;
};

type UpdateModelProviderStatusRequest = {
  status: 'active' | 'disabled';
};

function toModelProviderKind(value: string): ModelProviderKind {
  if (value === 'openai' || value === 'anthropic' || value === 'self_hosted') {
    return value;
  }

  return 'self_hosted';
}

function toModelProviderStatus(value: string): ModelProviderStatus {
  return value?.toLowerCase() === 'disabled' ? 'Disabled' : 'Active';
}

function toLastTestStatus(value?: string | null): 'failed' | 'passed' | undefined {
  const normalized = value?.toLowerCase();

  if (normalized === 'passed' || normalized === 'ok' || normalized === 'success') {
    return 'passed';
  }

  if (normalized === 'failed' || normalized === 'error') {
    return 'failed';
  }

  return undefined;
}

function toModelProvider(response: ModelProviderResponse): ModelProvider {
  return {
    clearance: response.clearance ?? null,
    embeddingModel: response.embedding_model ?? null,
    pricing: response.pricing
      ? {
          inputMicrosPerMillion: response.pricing.input_micros_per_million,
          outputMicrosPerMillion: response.pricing.output_micros_per_million,
        }
      : null,
    endpoint: response.endpoint ?? '',
    hasCredential: Boolean(response.has_credential),
    id: response.id,
    kind: toModelProviderKind(response.kind),
    lastTestMessage: response.last_test_message ?? undefined,
    lastTestStatus: toLastTestStatus(response.last_test_status),
    lastTestedAt: parseBackendTimestamp(response.last_tested_at) ?? undefined,
    model: response.model ?? '',
    name: response.name ?? '',
    status: toModelProviderStatus(response.status),
  };
}

function getTenantModelProvidersEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/model-providers`;
}

export async function getTenantModelProviders(
  orgSlug: string,
  tenantSlug: string,
): Promise<ModelProvider[]> {
  const response = await getList<ModelProviderResponse[]>(
    getTenantModelProvidersEndpoint(orgSlug, tenantSlug),
  );

  return response.map(toModelProvider);
}

export async function connectTenantModelProvider(
  orgSlug: string,
  tenantSlug: string,
  payload: ConnectModelProviderInput,
): Promise<ConnectModelProviderResponse> {
  return createResource<ConnectModelProviderResponse, ConnectModelProviderRequest>(
    getTenantModelProvidersEndpoint(orgSlug, tenantSlug),
    {
      api_key: payload.apiKey?.trim() ? payload.apiKey.trim() : null,
      endpoint: payload.endpoint,
      kind: payload.kind,
      model: payload.model,
      name: payload.name,
    },
  );
}

export async function testTenantModelProvider(
  orgSlug: string,
  tenantSlug: string,
  providerId: string,
): Promise<ModelProviderTestResult> {
  const response = await apiClient.post<ModelProviderTestResult>(
    `${getTenantModelProvidersEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(providerId)}/test`,
  );

  return response.data;
}

export async function deleteTenantModelProvider(
  orgSlug: string,
  tenantSlug: string,
  providerId: string,
): Promise<void> {
  await deleteResource<void>(getTenantModelProvidersEndpoint(orgSlug, tenantSlug), providerId);
}

export async function updateTenantModelProviderStatus(
  orgSlug: string,
  tenantSlug: string,
  providerId: string,
  status: ModelProviderStatus,
): Promise<void> {
  await patchResource<void, UpdateModelProviderStatusRequest>(
    getTenantModelProvidersEndpoint(orgSlug, tenantSlug),
    providerId,
    { status: status === 'Active' ? 'active' : 'disabled' },
  );
}

/** Has a provider offer an embedding model beside its chat model; `null` offers none. */
export async function setTenantModelProviderEmbeddings(
  orgSlug: string,
  tenantSlug: string,
  providerId: string,
  embeddingModel: string | null,
): Promise<void> {
  await apiClient.put(
    `${getTenantModelProvidersEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(providerId)}/embeddings`,
    { embedding_model: embeddingModel },
  );
}

/** Sets the most sensitive data runs and memories may send a provider. */
export async function setTenantModelProviderClearance(
  orgSlug: string,
  tenantSlug: string,
  providerId: string,
  clearance: string,
): Promise<void> {
  await apiClient.put(
    `${getTenantModelProvidersEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(providerId)}/clearance`,
    { clearance },
  );
}

export async function executeTenantModelProviderAction(
  orgSlug: string,
  tenantSlug: string,
  provider: ModelProvider,
  action: ModelProviderAction,
): Promise<void> {
  if (action === 'Enable provider') {
    await updateTenantModelProviderStatus(orgSlug, tenantSlug, provider.id, 'Active');
    return;
  }

  if (action === 'Disable provider') {
    await updateTenantModelProviderStatus(orgSlug, tenantSlug, provider.id, 'Disabled');
    return;
  }

  await deleteTenantModelProvider(orgSlug, tenantSlug, provider.id);
}
