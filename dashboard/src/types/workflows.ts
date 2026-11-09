import type { WorkflowGraph, WorkflowStepPosition, WorkflowTrigger } from '@/types/workflow-graph';

export type {
  WorkflowEdge as EdgeBody,
  WorkflowGraph as GraphBody,
  WorkflowNode as NodeBody,
  WorkflowStepPosition as StepPositionBody,
  WorkflowTrigger as TriggerBody,
} from '@/types/workflow-graph';

export type WorkflowStatus = 'draft' | 'published' | 'archived';

/** Why a version in service starts nothing until a next version is published. */
export type NeedsAccountReason =
  'gone' | 'disabled' | 'owner_cannot_lend' | 'not_lent' | 'not_for_this_use';

export type WorkflowNeedsAccount = {
  accountId: string;
  at: string;
  reason: NeedsAccountReason | string;
};

export type Workflow = {
  createdAt: string;
  createdBy: string;
  description: string | null;
  editedBy: string;
  failureAlert: string;
  graph: WorkflowGraph;
  id: string;
  layout: WorkflowStepPosition[];
  name: string;
  needsAccount: WorkflowNeedsAccount | null;
  publishedBy: string | null;
  revision: string;
  runLimitSeconds: number;
  status: WorkflowStatus | string;
  trigger: WorkflowTrigger;
  updatedAt: string;
  version: number;
};

export type WorkflowSortField = 'name' | 'created_at' | 'updated_at';

export type WorkflowList = {
  items: Workflow[];
  nextCursor: string | null;
};

export type ExecutionEnd = 'succeeded' | 'failed' | 'cancelled' | 'timed_out' | 'loop_ended';

export type ExecutionStatus = 'running' | ExecutionEnd;

export type StepPhase =
  'waiting' | 'ready' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'stopped' | 'abandoned';

export type ExecutionKind = 'real' | 'tests';

export type ExecutionMode = 'live' | 'test';

export type StepFailure = { code: string; detail: string };

export type LoopProgress = {
  approval: string | null;
  done: number;
  executions: string[];
  items: number;
};

export type StepState = {
  exposure: string | null;
  failure: StepFailure | null;
  input: unknown;
  key: string;
  name: string;
  output: unknown;
  passes: LoopProgress | null;
  phase: StepPhase | string;
  port: string | null;
  withheld: boolean;
};

export type ExecutionPass = { executionId: string; index: number; step: string };

export type Execution = {
  actingFor: string;
  cause: string;
  createdAt: string;
  deadline: string;
  exposure: string;
  id: string;
  input: unknown;
  inputWithheld: boolean;
  mode: ExecutionMode | string;
  pass: ExecutionPass | null;
  status: ExecutionStatus | string;
  steps: StepState[];
  updatedAt: string;
  version: number;
  workflowId: string;
};

export type ExecutionList = {
  items: Execution[];
  nextCursor: string | null;
};

/** Where an execution stands after a decision on it. */
export type ExecutionDecided = { executionId: string; status: ExecutionStatus | string };

export type ExposureLevel = 'public' | 'internal' | 'confidential' | 'restricted';

export type AccountSharing = 'owner_only' | 'tenant';

export type WorkflowAccount = {
  createdAt: string;
  id: string;
  integration: string;
  name: string;
  operations: string[] | null;
  owner: string;
  sharing: AccountSharing | string;
  status: 'enabled' | 'disabled' | string;
  updatedAt: string;
};

export type WorkflowAccountList = {
  items: WorkflowAccount[];
  nextCursor: string | null;
};

export type WorkflowAccountChange =
  | { change: 'enable' }
  | { change: 'disable' }
  | { change: 'replace_credential'; credential: string }
  | { change: 'share_with_tenant' }
  | { change: 'keep_to_owner' }
  | { change: 'limit_to'; operations: string[] | null }
  | { change: 'rename'; name: string };

export type IntegrationConnecting = 'sign_in' | 'credential' | string;

export type WorkflowIntegration = {
  brand: string;
  connecting: IntegrationConnecting;
  description: string;
  icon: string;
  key: string;
  picture: string | null;
  signInAsksFor: string | null;
  title: string;
};

export type OperationPickerRef = { dependsOn: string | null; filledBy: string };

export type OperationChoice = { label: string; tone: string; value: string };

export type OperationInputForm = {
  block: string;
  choices: OperationChoice[];
  example: string | null;
  group: string;
  label: string;
  picker: OperationPickerRef | null;
  style: string;
  warning: string | null;
};

export type OperationInput = {
  description: string;
  form: OperationInputForm | null;
  name: string;
  required: boolean;
};

export type OperationOutput = { description: string; path: string };

export type OperationPreview = { kind: string; parts: { input: string; part: string }[] };

export type WorkflowOperation = {
  ceiling: string;
  description: string;
  effect: string;
  inputs: OperationInput[];
  integration: string;
  needsAccount: boolean;
  operation: string;
  outputs: OperationOutput[];
  preview: OperationPreview | null;
  title: string;
};

export type WorkflowRunStep = {
  orgSlug: string;
  runId: string;
  step: string;
  tenantSlug: string;
};

/** One page of the items a loop asks a single approval for. */
export type LoopApprovalPage = {
  actionClass: string;
  approversNeeded: number;
  closesAt: string;
  items: { item: unknown; position: number }[];
  limit: number;
  nextCursor: string | null;
  openedAt: string;
  shared: unknown;
  shown: number;
  summary: string;
  total: number;
};
