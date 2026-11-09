import { apiClient } from '@/lib/api/client';
import { buildSortParam } from '@/lib/api/crud';
import type {
  Sandbox,
  SandboxDetail,
  SandboxHeldAgent,
  SandboxList,
  SandboxPushInput,
  SandboxRegistry,
  SandboxRuntime,
  SandboxSortField,
  SandboxTrial,
  SandboxVersion,
  SaveSandboxVersionInput,
  WriteSandboxCodeInput,
  WrittenSandboxCode,
} from '@/types/sandbox';

type SandboxResponse = {
  created_at: string;
  created_by: string;
  id: string;
  kind: string;
  language?: string | null;
  latest_version: number;
  name: string;
  status: string;
  updated_at: string;
};

type PageResponse<Item> = {
  items: Item[];
  limit: number;
  next_cursor?: string | null;
};

type HeldAgentResponse = {
  agent_id: string;
  approval_classes?: string[];
  ask_past_micros?: number | null;
  goal: string;
  max_steps: number;
  provider_id: string;
  purpose?: string[];
  spend_cap_micros: number;
  tools?: string[];
  tries: number;
};

type BuildResponse = {
  bytes?: number | null;
  detail?: string | null;
  digest?: string | null;
  failure?: string | null;
  findings?: { high: number; low: number; medium: number } | null;
  status: string;
  unlisted?: string[];
};

type VersionResponse = {
  agent?: HeldAgentResponse | null;
  allowed_hosts: string[];
  build: BuildResponse;
  code?: string | null;
  created_at: string;
  id: string;
  image: string;
  image_bytes?: number | null;
  imported_from?: {
    commit: string;
    integration: string;
    path: string;
    repository: string;
  } | null;
  kind: string;
  memory_mib: number;
  number: number;
  packages: { name: string; version: string }[];
  run_seconds: number;
  runtime?: string | null;
  sandbox_id: string;
  saved_by: string;
  updated_at: string;
};

type SandboxDetailResponse = {
  sandbox: SandboxResponse;
  versions: PageResponse<VersionResponse>;
};

type TrialResponse = {
  created_at: string;
  failure?: { code: string; detail: string } | null;
  id: string;
  input: unknown;
  output?: unknown;
  sandbox_id: string;
  started_by: string;
  status: string;
  updated_at: string;
  version_id: string;
};

type RegistryResponse = {
  allowed_by: string;
  created_at: string;
  host: string;
  id: string;
  login: string;
  username?: string | null;
};

type GetSandboxesParams = {
  after?: string;
  limit?: number;
  sortDirection?: 'asc' | 'desc';
  sortField?: SandboxSortField;
};

type CreateSandboxInput = {
  kind: 'code' | 'image';
  language: string | null;
  name: string;
};

function getSandboxesEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/sandboxes`;
}

function getSandboxEndpoint(orgSlug: string, tenantSlug: string, sandboxId: string) {
  return `${getSandboxesEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(sandboxId)}`;
}

function toSandbox(response: SandboxResponse): Sandbox {
  return {
    createdAt: response.created_at,
    createdBy: response.created_by,
    id: response.id,
    kind: response.kind,
    language: response.language ?? null,
    latestVersion: response.latest_version,
    name: response.name,
    status: response.status,
    updatedAt: response.updated_at,
  };
}

function toHeldAgent(response: HeldAgentResponse): SandboxHeldAgent {
  return {
    agentId: response.agent_id,
    approvalClasses: response.approval_classes ?? [],
    askPastMicros: response.ask_past_micros ?? null,
    goal: response.goal,
    maxSteps: response.max_steps,
    providerId: response.provider_id,
    purpose: response.purpose ?? [],
    spendCapMicros: response.spend_cap_micros,
    tools: response.tools ?? [],
    tries: response.tries,
  };
}

function toVersion(response: VersionResponse): SandboxVersion {
  return {
    agent: response.agent ? toHeldAgent(response.agent) : null,
    allowedHosts: response.allowed_hosts,
    build: {
      bytes: response.build.bytes ?? null,
      detail: response.build.detail ?? null,
      digest: response.build.digest ?? null,
      failure: response.build.failure ?? null,
      findings: response.build.findings ?? null,
      status: response.build.status,
      unlisted: response.build.unlisted ?? [],
    },
    code: response.code ?? null,
    createdAt: response.created_at,
    id: response.id,
    image: response.image,
    imageBytes: response.image_bytes ?? null,
    importedFrom: response.imported_from ?? null,
    kind: response.kind,
    memoryMib: response.memory_mib,
    number: response.number,
    packages: response.packages,
    runSeconds: response.run_seconds,
    runtime: response.runtime ?? null,
    sandboxId: response.sandbox_id,
    savedBy: response.saved_by,
    updatedAt: response.updated_at,
  };
}

function toTrial(response: TrialResponse): SandboxTrial {
  return {
    createdAt: response.created_at,
    failure: response.failure ?? null,
    id: response.id,
    input: response.input,
    output: response.output ?? null,
    sandboxId: response.sandbox_id,
    startedBy: response.started_by,
    status: response.status,
    updatedAt: response.updated_at,
    versionId: response.version_id,
  };
}

function toRegistry(response: RegistryResponse): SandboxRegistry {
  return {
    allowedBy: response.allowed_by,
    createdAt: response.created_at,
    host: response.host,
    id: response.id,
    login: response.login,
    username: response.username ?? null,
  };
}

function toHeldAgentBody(agent: SandboxHeldAgent): HeldAgentResponse {
  return {
    agent_id: agent.agentId,
    approval_classes: agent.approvalClasses,
    ask_past_micros: agent.askPastMicros,
    goal: agent.goal,
    max_steps: agent.maxSteps,
    provider_id: agent.providerId,
    purpose: agent.purpose,
    spend_cap_micros: agent.spendCapMicros,
    tools: agent.tools,
    tries: agent.tries,
  };
}

function toSaveVersionBody(input: SaveSandboxVersionInput) {
  const limits = {
    allowed_hosts: input.allowedHosts,
    memory_mib: input.memoryMib,
    run_seconds: input.runSeconds,
  };

  if (input.image) {
    return { ...limits, image: input.image };
  }

  return {
    ...limits,
    agent: input.agent ? toHeldAgentBody(input.agent) : null,
    code: input.code ?? undefined,
    import: input.import
      ? {
          account_id: input.import.accountId,
          path: input.import.path,
          ref: input.import.ref,
          repository: input.import.repository,
        }
      : undefined,
    packages: input.packages,
    runtime: input.runtime,
  };
}

/** One page of the tenant's sandboxes, archived ones among them. */
export async function getSandboxes(
  orgSlug: string,
  tenantSlug: string,
  { after, limit, sortDirection, sortField }: GetSandboxesParams = {},
): Promise<SandboxList> {
  const { data } = await apiClient.get<PageResponse<SandboxResponse>>(
    getSandboxesEndpoint(orgSlug, tenantSlug),
    { params: { after, limit, sort: buildSortParam(sortField, sortDirection) } },
  );

  return { items: data.items.map(toSandbox), nextCursor: data.next_cursor ?? null };
}

/** Makes a sandbox with no version yet. Its kind and language never change. */
export async function createSandbox(
  orgSlug: string,
  tenantSlug: string,
  input: CreateSandboxInput,
): Promise<Sandbox> {
  const { data } = await apiClient.post<SandboxResponse>(
    getSandboxesEndpoint(orgSlug, tenantSlug),
    input,
  );

  return toSandbox(data);
}

/** The sandbox and one page of its versions, newest first. */
export async function getSandbox(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  { after, limit }: { after?: string; limit?: number } = {},
): Promise<SandboxDetail> {
  const { data } = await apiClient.get<SandboxDetailResponse>(
    getSandboxEndpoint(orgSlug, tenantSlug, sandboxId),
    { params: { after, limit } },
  );

  return {
    sandbox: toSandbox(data.sandbox),
    versions: {
      items: data.versions.items.map(toVersion),
      nextCursor: data.versions.next_cursor ?? null,
    },
  };
}

/** Archives a sandbox: nothing new is saved or picked of it again. */
export async function archiveSandbox(orgSlug: string, tenantSlug: string, sandboxId: string) {
  const { data } = await apiClient.post<SandboxResponse>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/archive`,
  );

  return toSandbox(data);
}

/** The runtimes a new version may pick now. A retired runtime is left out. */
export async function getSandboxRuntimes(
  orgSlug: string,
  tenantSlug: string,
): Promise<SandboxRuntime[]> {
  const { data } = await apiClient.get<SandboxRuntime[]>(
    `${getSandboxesEndpoint(orgSlug, tenantSlug)}/runtimes`,
  );

  return data;
}

/** Saves the next version. Its package bundle is then built, or its image scanned. */
export async function saveSandboxVersion(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  input: SaveSandboxVersionInput,
): Promise<SandboxVersion> {
  const { data } = await apiClient.post<VersionResponse>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/versions`,
    toSaveVersionBody(input),
  );

  return toVersion(data);
}

/** Tries a built version on sample input. It answers at once; read the trial for the result. */
export async function startSandboxTrial(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  versionId: string,
  input: Record<string, unknown>,
): Promise<SandboxTrial> {
  const { data } = await apiClient.post<TrialResponse>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/versions/${encodeURIComponent(versionId)}/trials`,
    { input },
  );

  return toTrial(data);
}

/** One trial. It is kept for a day after it ended, then answers 404. */
export async function getSandboxTrial(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  trialId: string,
): Promise<SandboxTrial> {
  const { data } = await apiClient.get<TrialResponse>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/trials/${encodeURIComponent(trialId)}`,
  );

  return toTrial(data);
}

/** Sends a copy of a version to a repository. The saved version stays the one that runs. */
export async function pushSandboxVersion(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  versionId: string,
  input: SandboxPushInput,
): Promise<SandboxVersion> {
  const { data } = await apiClient.post<VersionResponse>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/versions/${encodeURIComponent(versionId)}/pushes`,
    {
      account_id: input.accountId,
      branch: input.branch,
      folder: input.folder,
      repository: input.repository,
    },
  );

  return toVersion(data);
}

/** Has the tenant's model write the code, or fix code that failed. Nothing is saved. */
export async function writeSandboxCode(
  orgSlug: string,
  tenantSlug: string,
  sandboxId: string,
  input: WriteSandboxCodeInput,
): Promise<WrittenSandboxCode> {
  const { data } = await apiClient.post<WrittenSandboxCode>(
    `${getSandboxEndpoint(orgSlug, tenantSlug, sandboxId)}/suggestions`,
    {
      fix: input.fix,
      inputs: input.inputs,
      packages: input.packages,
      provider_id: input.providerId,
      words: input.words,
    },
  );

  return data;
}

/** The registries image sandboxes may take the company's images from. Passwords never come back. */
export async function getSandboxRegistries(
  orgSlug: string,
  tenantSlug: string,
): Promise<SandboxRegistry[]> {
  const { data } = await apiClient.get<RegistryResponse[]>(
    `${getSandboxesEndpoint(orgSlug, tenantSlug)}/registries`,
  );

  return data.map(toRegistry);
}

/** Allows a registry, pulled with a login or none. The password is sealed before it is kept. */
export async function allowSandboxRegistry(
  orgSlug: string,
  tenantSlug: string,
  input: { host: string; password: string | null; username: string | null },
): Promise<SandboxRegistry> {
  const { data } = await apiClient.post<RegistryResponse>(
    `${getSandboxesEndpoint(orgSlug, tenantSlug)}/registries`,
    input,
  );

  return toRegistry(data);
}

/** Takes a registry off the list. Versions whose image it keeps stop running. */
export async function removeSandboxRegistry(
  orgSlug: string,
  tenantSlug: string,
  registryId: string,
): Promise<void> {
  await apiClient.delete(
    `${getSandboxesEndpoint(orgSlug, tenantSlug)}/registries/${encodeURIComponent(registryId)}`,
  );
}
