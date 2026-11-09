// A workflow's graph exactly as the API reads and writes it, in snake_case. A
// body read from the API is sent back as it came, so a field a newer backend
// adds is never dropped by a mapping.

export type WorkflowPort = 'next' | 'when_false' | 'when_true';

export type WorkflowJoin = 'all' | 'any';

export type WorkflowSource = { from: 'input'; path: string } | { from: 'literal'; value: unknown };

export type WorkflowMappedField = WorkflowSource & { field: string };

export type WorkflowClauseTest =
  | { test: 'exists' }
  | { test: 'is_empty' }
  | { test: 'equals'; value: unknown }
  | { test: 'not_equals'; value: unknown }
  | { test: 'contains'; value: string }
  | { test: 'greater_than'; value: number }
  | { test: 'less_than'; value: number };

export type WorkflowClause = WorkflowClauseTest & { path: string };

export type WorkflowActionStep = {
  account_id: string | null;
  ceiling: string;
  effect: string;
  inputs: WorkflowMappedField[];
  integration: string;
  kind: 'action';
  operation: string;
};

export type WorkflowConditionStep = {
  clauses: WorkflowClause[];
  kind: 'condition';
  matching: WorkflowJoin;
};

export type WorkflowTransformStep = {
  fields: WorkflowMappedField[];
  kind: 'transform';
};

export type WorkflowApprovalStep = {
  action_class: string;
  covers?: 'each_pass' | 'whole_loop';
  kind: 'approval';
  slack?: { account_id: string; channel: string };
  summary: string;
  window_seconds: number;
};

export type WorkflowWorkingHours = {
  closes: string;
  days: string[];
  opens: string;
  timezone: string;
};

export type WorkflowWaitStep = {
  duration_seconds?: number;
  kind: 'wait';
  working_hours?: WorkflowWorkingHours;
};

export type WorkflowLoopStep = {
  at_once: number;
  inputs: WorkflowMappedField[];
  kind: 'loop';
  most_items: number;
  over: string;
  steps: WorkflowGraph;
};

export type WorkflowCodeStep = {
  inputs: WorkflowMappedField[];
  kind: 'code';
  sandbox_version_id: string;
};

export type WorkflowGuardrailStep = {
  banned_words?: string[];
  checks: string[];
  kind: 'guardrail';
  on_finding?: 'record' | 'remove' | 'stop';
  personal_from?: string;
  text: string;
};

export type WorkflowAgentRunStep = {
  agent_id: string;
  approval_classes?: string[];
  ask_past_micros?: number;
  checks?: string;
  goal: string;
  inputs: WorkflowMappedField[];
  kind: 'agent_run';
  max_steps: number;
  provider_id: string;
  purpose?: string[];
  spend_cap_micros?: number;
  tools?: string[];
};

export type WorkflowStep =
  | WorkflowActionStep
  | WorkflowAgentRunStep
  | WorkflowApprovalStep
  | WorkflowCodeStep
  | WorkflowConditionStep
  | WorkflowGuardrailStep
  | WorkflowLoopStep
  | WorkflowTransformStep
  | WorkflowWaitStep;

export type WorkflowStepKind = WorkflowStep['kind'];

export type WorkflowNode = WorkflowStep & {
  join?: WorkflowJoin;
  key: string;
  name: string;
};

export type WorkflowEdge = {
  from: string;
  port: WorkflowPort;
  to: string;
};

export type WorkflowGraph = {
  edges: WorkflowEdge[];
  nodes: WorkflowNode[];
};

export type WorkflowTrigger =
  | { type: 'manual' }
  | { type: 'schedule'; cron: string }
  | { type: 'webhook' }
  | { type: 'event'; event: string }
  | {
      account_id: string;
      event: string;
      filters?: Record<string, string>;
      integration: string;
      type: 'service';
    }
  | { change: string; type: 'before' };

export type WorkflowStepPosition = {
  key: string;
  x: number;
  y: number;
};

export type WorkflowFailureAlert = 'administrators' | 'also_authors';

export type WorkflowDraftEdit =
  | { edit: 'arrange'; layout: WorkflowStepPosition[] }
  | { edit: 'change_failure_alert'; failure_alert: WorkflowFailureAlert }
  | { edit: 'change_run_limit'; run_limit_seconds: number }
  | { edit: 'change_trigger'; trigger: WorkflowTrigger }
  | { description: string | null; edit: 'describe' }
  | { edit: 'rename'; name: string }
  | { edit: 'replace_steps'; graph: WorkflowGraph };

export type NewWorkflow = {
  description?: string;
  failure_alert?: WorkflowFailureAlert;
  graph: WorkflowGraph;
  layout: WorkflowStepPosition[];
  name: string;
  run_limit_seconds: number;
  trigger: WorkflowTrigger;
};

/** One input a model proposed: a value written out, or a path to earlier data. */
export type ProposedInput = { name: string; path?: string; text?: string };

export type ProposedStep = { key: string; title: string } & (
  | { integration: string; inputs: ProposedInput[]; kind: 'action'; operation: string }
  | { goal: string; kind: 'agent_run' }
  | { equals?: string; kind: 'condition'; path: string }
  | { class: string; kind: 'approval'; summary: string }
  | { kind: 'wait'; seconds: number }
);

export type ProposedTrigger =
  | { kind: 'manual' }
  | { kind: 'webhook' }
  | { cron: string; kind: 'schedule' }
  | { event: string; integration: string; kind: 'service_event' };

/** Steps a model proposed. Nothing is saved until the builder keeps them. */
export type WorkflowProposal = {
  edges: { from?: string; port: WorkflowPort; to: string }[];
  notes: string[];
  steps: ProposedStep[];
  trigger?: ProposedTrigger;
};
