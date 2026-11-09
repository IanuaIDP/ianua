import type { OperationLookup } from '@/components/dashboard/workflows/builder/step-issues';
import type {
  ProposedStep,
  WorkflowEdge,
  WorkflowMappedField,
  WorkflowNode,
  WorkflowProposal,
  WorkflowTrigger,
} from '@/types/workflow-graph';
import type { WorkflowAccount } from '@/types/workflows';

const DAY_SECONDS = 86_400;
const DEFAULT_AGENT_STEPS = 10;

type ConvertContext = {
  accounts: WorkflowAccount[];
  lookup: OperationLookup;
  providerId: string;
};

function getOnlyAccount(accounts: WorkflowAccount[], integration: string) {
  const usable = accounts.filter(
    (account) => account.integration === integration && account.status !== 'disabled',
  );

  return usable.length === 1 ? usable[0].id : null;
}

function toMapped(
  inputs: Extract<ProposedStep, { kind: 'action' }>['inputs'],
): WorkflowMappedField[] {
  return inputs.flatMap((input): WorkflowMappedField[] => {
    if (input.path) {
      return [{ field: input.name, from: 'input', path: input.path }];
    }

    return input.text ? [{ field: input.name, from: 'literal', value: input.text }] : [];
  });
}

function toNode(step: ProposedStep, context: ConvertContext): WorkflowNode {
  const base = { key: step.key, name: step.title };

  switch (step.kind) {
    case 'action': {
      const operation = context.lookup(step.integration, step.operation);

      return {
        ...base,
        account_id: getOnlyAccount(context.accounts, step.integration),
        ceiling: operation?.ceiling ?? 'internal',
        effect: operation?.effect ?? 'undeclared',
        inputs: toMapped(step.inputs),
        integration: step.integration,
        kind: 'action',
        operation: step.operation,
      };
    }
    case 'agent_run':
      return {
        ...base,
        agent_id: '',
        approval_classes: [],
        goal: step.goal,
        inputs: [],
        kind: 'agent_run',
        max_steps: DEFAULT_AGENT_STEPS,
        provider_id: context.providerId,
        purpose: [],
        tools: [],
      };
    case 'condition':
      return {
        ...base,
        clauses:
          step.equals === undefined
            ? [{ path: step.path, test: 'exists' }]
            : [{ path: step.path, test: 'equals', value: step.equals }],
        kind: 'condition',
        matching: 'all',
      };
    case 'approval':
      return {
        ...base,
        action_class: step.class,
        kind: 'approval',
        summary: step.summary,
        window_seconds: DAY_SECONDS,
      };
    default:
      return { ...base, duration_seconds: step.seconds, kind: 'wait' };
  }
}

export function toProposedTrigger(
  proposal: WorkflowProposal,
  accounts: WorkflowAccount[],
): WorkflowTrigger | null {
  const trigger = proposal.trigger;

  if (!trigger) {
    return null;
  }

  switch (trigger.kind) {
    case 'schedule':
      return { cron: trigger.cron, type: 'schedule' };
    case 'webhook':
      return { type: 'webhook' };
    case 'service_event':
      return {
        account_id: getOnlyAccount(accounts, trigger.integration) ?? '',
        event: trigger.event,
        filters: {},
        integration: trigger.integration,
        type: 'service',
      };
    default:
      return { type: 'manual' };
  }
}

/** Proposed steps as nodes and arrows, with keys free in this workflow. */
export function toProposedSteps(
  proposal: WorkflowProposal,
  context: ConvertContext & {
    after: string | null;
    keep: Set<string>;
    takenKeys: string[];
  },
): { edges: WorkflowEdge[]; nodes: WorkflowNode[] } {
  const taken = new Set(context.takenKeys);
  const rename = new Map<string, string>();

  for (const step of proposal.steps.filter((item) => context.keep.has(item.key))) {
    let key = step.key;
    let number = 2;

    while (taken.has(key)) {
      key = `${step.key}-${number}`;
      number += 1;
    }

    taken.add(key);
    rename.set(step.key, key);
  }

  const nodes = proposal.steps
    .filter((step) => rename.has(step.key))
    .map((step) => ({ ...toNode(step, context), key: rename.get(step.key) ?? step.key }));
  const edges = proposal.edges.flatMap((edge): WorkflowEdge[] => {
    const to = rename.get(edge.to);
    const from = edge.from === undefined ? context.after : rename.get(edge.from);

    return to && from ? [{ from, port: edge.port, to }] : [];
  });

  return { edges, nodes };
}
