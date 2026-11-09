import { apiClient } from '@/lib/api/client';
import type {
  AddableStagePayload,
  Pipeline,
  PipelineAction,
  PipelineStatus,
  PipelineSummary,
  Stage,
  StageAction,
  StageKind,
  StageStatus,
} from '@/types/pipeline';
import { formatBackendDate } from '@/utils/date';

type StageKindResponse = string | Record<string, unknown> | null;

type StageResponse = {
  enabled?: boolean | null;
  id: string;
  kind?: StageKindResponse;
  mandatory?: boolean | null;
  position?: number | null;
};

type PipelineResponse = {
  created_at?: string | null;
  id: string;
  name?: string | null;
  stages?: StageResponse[] | null;
  status?: string | null;
  updated_at?: string | null;
};

type PipelineSummaryResponse = {
  created_at?: string | null;
  id: string;
  name?: string | null;
  route_count?: number | null;
  stage_count?: number | null;
  status?: string | null;
  updated_at?: string | null;
};

type CreatePipelineResponse = {
  id: string;
};

type WasmModuleResponse = {
  module_ref: string;
};

function toPipelineStatus(value?: string | null): PipelineStatus {
  if (value === 'Active' || value === 'Disabled') {
    return value;
  }

  return 'Draft';
}

function toStageStatus(enabled?: boolean | null): StageStatus {
  return enabled === false ? 'Disabled' : 'Enabled';
}

function toStageKind(value: StageKindResponse): StageKind {
  if (typeof value === 'string' && value) {
    return value as StageKind;
  }

  if (value && typeof value === 'object') {
    const variantName = Object.keys(value)[0];

    if (variantName) {
      return variantName as StageKind;
    }
  }

  return 'Custom';
}

function toStage(response: StageResponse): Stage {
  return {
    id: response.id,
    isMandatory: Boolean(response.mandatory),
    kind: toStageKind(response.kind ?? null),
    position: response.position ?? 0,
    status: toStageStatus(response.enabled),
  };
}

function toPipeline(response: PipelineResponse): Pipeline {
  return {
    created: formatBackendDate(response.created_at),
    id: response.id,
    name: response.name || 'Untitled pipeline',
    stages: (response.stages ?? []).map(toStage).sort((a, b) => a.position - b.position),
    status: toPipelineStatus(response.status),
    updated: formatBackendDate(response.updated_at),
  };
}

function toPipelineSummary(response: PipelineSummaryResponse): PipelineSummary {
  return {
    created: formatBackendDate(response.created_at),
    id: response.id,
    name: response.name || 'Untitled pipeline',
    routeCount: response.route_count ?? 0,
    stageCount: response.stage_count ?? 0,
    status: toPipelineStatus(response.status),
    updated: formatBackendDate(response.updated_at),
  };
}

function getPipelinesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/pipelines`;
}

function getPipelineEndpoint(orgSlug: string, tenantSlug: string, pipelineId: string) {
  return `${getPipelinesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(pipelineId)}`;
}

export async function getTenantPipelines(
  orgSlug: string,
  tenantSlug: string,
): Promise<PipelineSummary[]> {
  const response = await apiClient.get<PipelineSummaryResponse[]>(
    getPipelinesEndpoint(orgSlug, tenantSlug),
  );

  return (response.data ?? []).map(toPipelineSummary);
}

export async function getTenantPipeline(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
): Promise<Pipeline> {
  const response = await apiClient.get<PipelineResponse>(
    getPipelineEndpoint(orgSlug, tenantSlug, pipelineId),
  );

  return toPipeline(response.data);
}

export async function createTenantPipeline(
  orgSlug: string,
  tenantSlug: string,
  name: string,
): Promise<string> {
  const response = await apiClient.post<CreatePipelineResponse>(
    getPipelinesEndpoint(orgSlug, tenantSlug),
    { name },
  );

  return response.data.id;
}

export async function deleteTenantPipeline(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
): Promise<void> {
  await apiClient.delete(getPipelineEndpoint(orgSlug, tenantSlug, pipelineId));
}

export async function activateTenantPipeline(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
): Promise<void> {
  await apiClient.post(`${getPipelineEndpoint(orgSlug, tenantSlug, pipelineId)}/activate`);
}

export async function disableTenantPipeline(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
): Promise<void> {
  await apiClient.post(`${getPipelineEndpoint(orgSlug, tenantSlug, pipelineId)}/disable`);
}

export async function executePipelineAction(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  action: PipelineAction,
): Promise<void> {
  if (action === 'Activate') {
    await activateTenantPipeline(orgSlug, tenantSlug, pipelineId);
    return;
  }

  if (action === 'Disable') {
    await disableTenantPipeline(orgSlug, tenantSlug, pipelineId);
    return;
  }

  await deleteTenantPipeline(orgSlug, tenantSlug, pipelineId);
}

function toStageKindRequest(payload: AddableStagePayload): Record<string, unknown> {
  switch (payload.kind) {
    case 'Waf':
      return {
        Waf: {
          anomaly_threshold: payload.config.anomalyThreshold,
          max_body_bytes: payload.config.maxBodyBytes,
          rule_sets: payload.config.ruleSets,
        },
      };
    case 'RateLimit':
      return {
        RateLimit: {
          key_by: payload.config.keyBy,
          max_requests: payload.config.maxRequests,
          window_seconds: payload.config.windowSeconds,
        },
      };
    case 'CanaryToken':
      return { CanaryToken: { tokens: payload.config.tokens } };
    case 'GraphQl':
      return {
        GraphQl: {
          cost_per_complexity: payload.config.costPerComplexity,
          max_complexity: payload.config.maxComplexity,
          max_depth: payload.config.maxDepth,
        },
      };
    case 'RequestTransform':
      return {
        RequestTransform: {
          remove_headers: payload.config.removeHeaders,
          remove_query: payload.config.removeQuery,
          set_headers: payload.config.setHeaders,
          set_query: payload.config.setQuery,
        },
      };
    case 'ResponseTransform':
      return {
        ResponseTransform: {
          remove_headers: payload.config.removeHeaders,
          set_headers: payload.config.setHeaders,
        },
      };
    case 'TokenRateLimit':
      return {
        TokenRateLimit: {
          dialect: payload.config.dialect,
          key_by: payload.config.keyBy,
          max_tokens: payload.config.maxTokens,
          on_unknown: payload.config.onUnknown,
          window_seconds: payload.config.windowSeconds,
        },
      };
    case 'Custom':
      return {
        Custom: {
          max_memory_bytes: payload.config.maxMemoryBytes,
          module_ref: payload.config.moduleRef,
          timeout_ms: payload.config.timeoutMs,
        },
      };
    default:
      return payload;
  }
}

/**
 * Uploads a WebAssembly module and returns the reference a `Custom` stage
 * points at.
 *
 * Uploading stores the module and nothing else — no stage is created or
 * changed until the returned reference is added to one.
 */
export async function uploadWasmModule(
  orgSlug: string,
  tenantSlug: string,
  bytecodeBase64: string,
): Promise<string> {
  const response = await apiClient.post<WasmModuleResponse>(
    `${getPipelinesEndpoint(orgSlug, tenantSlug)}/wasm-modules`,
    { bytecode_base64: bytecodeBase64 },
  );

  return response.data.module_ref;
}

export async function addPipelineStage(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  payload: AddableStagePayload & { position: number },
): Promise<void> {
  await apiClient.post(`${getPipelineEndpoint(orgSlug, tenantSlug, pipelineId)}/stages`, {
    kind: toStageKindRequest(payload),
    position: payload.position,
  });
}

export async function removePipelineStage(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  stageId: string,
): Promise<void> {
  await apiClient.delete(
    `${getPipelineEndpoint(orgSlug, tenantSlug, pipelineId)}/stages/${encodeURIComponent(stageId)}`,
  );
}

export async function reorderPipelineStages(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  stageIds: string[],
): Promise<void> {
  await apiClient.put(`${getPipelineEndpoint(orgSlug, tenantSlug, pipelineId)}/stages/order`, {
    stage_ids: stageIds,
  });
}

export async function enablePipelineStage(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  stageId: string,
): Promise<void> {
  await apiClient.post(
    `${getPipelineEndpoint(
      orgSlug,
      tenantSlug,
      pipelineId,
    )}/stages/${encodeURIComponent(stageId)}/enable`,
  );
}

export async function disablePipelineStage(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  stageId: string,
): Promise<void> {
  await apiClient.post(
    `${getPipelineEndpoint(
      orgSlug,
      tenantSlug,
      pipelineId,
    )}/stages/${encodeURIComponent(stageId)}/disable`,
  );
}

export async function executeStageAction(
  orgSlug: string,
  tenantSlug: string,
  pipelineId: string,
  stage: Stage,
  action: StageAction,
): Promise<void> {
  if (action === 'Enable') {
    await enablePipelineStage(orgSlug, tenantSlug, pipelineId, stage.id);
    return;
  }

  if (action === 'Disable') {
    await disablePipelineStage(orgSlug, tenantSlug, pipelineId, stage.id);
    return;
  }

  await removePipelineStage(orgSlug, tenantSlug, pipelineId, stage.id);
}
