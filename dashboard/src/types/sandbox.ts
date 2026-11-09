export type SandboxKind = 'code' | 'image';

export type SandboxSortField = 'name' | 'updated_at';

export type Sandbox = {
  createdAt: string;
  createdBy: string;
  id: string;
  kind: SandboxKind | string;
  language: string | null;
  latestVersion: number;
  name: string;
  status: string;
  updatedAt: string;
};

export type SandboxList = {
  items: Sandbox[];
  nextCursor: string | null;
};

export type SandboxPackage = {
  name: string;
  version: string;
};

export type SandboxHeldAgent = {
  agentId: string;
  approvalClasses: string[];
  askPastMicros: number | null;
  goal: string;
  maxSteps: number;
  providerId: string;
  purpose: string[];
  spendCapMicros: number;
  tools: string[];
  tries: number;
};

export type SandboxBuildFindings = {
  high: number;
  low: number;
  medium: number;
};

export type SandboxBuild = {
  bytes: number | null;
  detail: string | null;
  digest: string | null;
  failure: string | null;
  findings: SandboxBuildFindings | null;
  status: string;
  unlisted: string[];
};

export type SandboxImportedFrom = {
  commit: string;
  integration: string;
  path: string;
  repository: string;
};

export type SandboxVersion = {
  agent: SandboxHeldAgent | null;
  allowedHosts: string[];
  build: SandboxBuild;
  code: string | null;
  createdAt: string;
  id: string;
  image: string;
  imageBytes: number | null;
  importedFrom: SandboxImportedFrom | null;
  kind: SandboxKind | string;
  memoryMib: number;
  number: number;
  packages: SandboxPackage[];
  runSeconds: number;
  runtime: string | null;
  sandboxId: string;
  savedBy: string;
  updatedAt: string;
};

export type SandboxDetail = {
  sandbox: Sandbox;
  versions: {
    items: SandboxVersion[];
    nextCursor: string | null;
  };
};

export type SandboxRuntime = {
  image: string;
  language: string;
  runtime: string;
};

export type SandboxImport = {
  accountId: string;
  path: string;
  ref: string;
  repository: string;
};

/** A next version: code under a runtime, code read from a repository, or a company's image. */
export type SaveSandboxVersionInput = {
  agent: SandboxHeldAgent | null;
  allowedHosts: string[];
  code: string | null;
  image: string | null;
  import: SandboxImport | null;
  memoryMib: number;
  packages: SandboxPackage[];
  runSeconds: number;
  runtime: string | null;
};

export type SandboxTrialFailure = {
  code: string;
  detail: string;
};

export type SandboxTrial = {
  createdAt: string;
  failure: SandboxTrialFailure | null;
  id: string;
  input: unknown;
  output: unknown;
  sandboxId: string;
  startedBy: string;
  status: string;
  updatedAt: string;
  versionId: string;
};

export type SandboxPushInput = {
  accountId: string;
  branch: string;
  folder: string;
  repository: string;
};

export type WriteSandboxCodeInput = {
  fix: { code: string; failure: string } | null;
  inputs: string[];
  packages: string[];
  providerId: string;
  words: string;
};

export type WrittenSandboxCode = {
  code: string;
  explanation: string;
};

export type SandboxRegistry = {
  allowedBy: string;
  createdAt: string;
  host: string;
  id: string;
  login: string;
  username: string | null;
};
