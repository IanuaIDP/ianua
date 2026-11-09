import {
  HIGH_RISK_EFFECTS,
  MAX_AGENT_STEPS,
  MAX_APPROVAL_WINDOW_SECONDS,
  MAX_WAIT_SECONDS,
  TRIGGER_KEY,
} from '@/components/dashboard/workflows/builder/constants';
import { isValidCron } from '@/components/dashboard/workflows/builder/cron';
import { getStepsBefore } from '@/components/dashboard/workflows/builder/graph';
import {
  getMappedSource,
  isSourceFilled,
  isValidFieldName,
  isValidPath,
} from '@/components/dashboard/workflows/builder/mapped-fields';
import type { WorkingCopy } from '@/components/dashboard/workflows/builder/working-copy';
import type {
  WorkflowNode,
  WorkflowTrigger,
  WorkflowActionStep,
  WorkflowAgentRunStep,
  WorkflowClause,
  WorkflowGuardrailStep,
  WorkflowLoopStep,
  WorkflowMappedField,
  WorkflowWaitStep,
} from '@/types/workflow-graph';
import type { WorkflowOperation } from '@/types/workflows';

export type StepIssueCode =
  | 'accountMissing'
  | 'versionMissing'
  | 'agentMissing'
  | 'askPastTooHigh'
  | 'bannedWordsMissing'
  | 'checksMissing'
  | 'goalEmpty'
  | 'hoursInvalid'
  | 'insideUnfinished'
  | 'maxStepsInvalid'
  | 'overMissing'
  | 'providerMissing'
  | 'slackIncomplete'
  | 'textMissing'
  | 'approvalMissing'
  | 'clauseEmpty'
  | 'clausesMissing'
  | 'durationInvalid'
  | 'fieldEmpty'
  | 'fieldsMissing'
  | 'inputEmpty'
  | 'nameEmpty'
  | 'operationGone'
  | 'readsLater'
  | 'summaryEmpty'
  | 'windowInvalid';

export type StepIssue = { code: StepIssueCode; values?: Record<string, string> };

export type OperationLookup = (integration: string, operation: string) => WorkflowOperation | null;

export function makeOperationLookup(operations: WorkflowOperation[] | undefined): OperationLookup {
  const byName = new Map(
    (operations ?? []).map((operation) => [
      `${operation.integration}/${operation.operation}`,
      operation,
    ]),
  );

  return (integration, operation) => byName.get(`${integration}/${operation}`) ?? null;
}

function getActionIssues(node: WorkflowActionStep, operation: WorkflowOperation): StepIssue[] {
  const issues: StepIssue[] = [];

  if (operation.needsAccount && !node.account_id) {
    issues.push({ code: 'accountMissing' });
  }

  for (const input of operation.inputs) {
    if (input.required && !isSourceFilled(getMappedSource(node.inputs, input.name))) {
      issues.push({
        code: 'inputEmpty',
        values: { field: input.form?.label ?? input.name },
      });
    }
  }

  return issues;
}

function isClauseFilled(clause: WorkflowClause) {
  if (!isValidPath(clause.path)) {
    return false;
  }

  if (clause.test === 'exists' || clause.test === 'is_empty') {
    return true;
  }

  if (clause.test === 'greater_than' || clause.test === 'less_than') {
    return Number.isFinite(clause.value);
  }

  return clause.value !== '' && clause.value !== undefined && clause.value !== null;
}

function getMappingIssues(fields: WorkflowMappedField[]): StepIssue[] {
  if (fields.length === 0) {
    return [{ code: 'fieldsMissing' }];
  }

  return fields.flatMap((field) =>
    isValidFieldName(field.field) && isSourceFilled(field)
      ? []
      : [{ code: 'fieldEmpty' as const, values: { field: field.field || '…' } }],
  );
}

function getWaitIssues(node: WorkflowWaitStep): StepIssue[] {
  if (node.working_hours) {
    const { closes, days, opens, timezone } = node.working_hours;
    const isClock = (value: string) => /^\d{1,2}:\d{2}$/.test(value);

    return days.length > 0 && isClock(opens) && isClock(closes) && timezone.trim()
      ? []
      : [{ code: 'hoursInvalid' }];
  }

  return node.duration_seconds !== undefined &&
    node.duration_seconds >= 1 &&
    node.duration_seconds <= MAX_WAIT_SECONDS
    ? []
    : [{ code: 'durationInvalid' }];
}

function getAgentIssues(node: WorkflowAgentRunStep): StepIssue[] {
  const issues: StepIssue[] = [];

  if (!node.agent_id) {
    issues.push({ code: 'agentMissing' });
  }

  if (!node.provider_id) {
    issues.push({ code: 'providerMissing' });
  }

  if (!node.goal.trim()) {
    issues.push({ code: 'goalEmpty' });
  }

  if (!(node.max_steps >= 1 && node.max_steps <= MAX_AGENT_STEPS)) {
    issues.push({ code: 'maxStepsInvalid' });
  }

  if (
    node.spend_cap_micros &&
    node.ask_past_micros &&
    node.ask_past_micros >= node.spend_cap_micros
  ) {
    issues.push({ code: 'askPastTooHigh' });
  }

  return issues;
}

function getGuardrailIssues(node: WorkflowGuardrailStep): StepIssue[] {
  const issues: StepIssue[] = [];

  if (!isValidPath(node.text)) {
    issues.push({ code: 'textMissing' });
  }

  if (node.checks.length === 0) {
    issues.push({ code: 'checksMissing' });
  }

  if (node.checks.includes('banned_words') && !node.banned_words?.length) {
    issues.push({ code: 'bannedWordsMissing' });
  }

  return issues;
}

function getLoopIssues(node: WorkflowLoopStep, lookup: OperationLookup): StepIssue[] {
  const issues: StepIssue[] = isValidPath(node.over) ? [] : [{ code: 'overMissing' }];
  const isUnfinished =
    node.steps.nodes.length === 0 ||
    node.steps.nodes.some((inner) => getStepIssues(inner, lookup).length > 0);

  return isUnfinished ? [...issues, { code: 'insideUnfinished' }] : issues;
}

/** What keeps a step from being sent to the server. A step with any stays in the browser. */
export function getStepIssues(node: WorkflowNode, lookup: OperationLookup): StepIssue[] {
  const naming: StepIssue[] = node.name.trim() ? [] : [{ code: 'nameEmpty' }];

  switch (node.kind) {
    case 'action': {
      const operation = lookup(node.integration, node.operation);

      return operation ? [...naming, ...getActionIssues(node, operation)] : naming;
    }
    case 'condition':
      return [
        ...naming,
        ...(node.clauses.length === 0 ? [{ code: 'clausesMissing' as const }] : []),
        ...(node.clauses.every(isClauseFilled) ? [] : [{ code: 'clauseEmpty' as const }]),
      ];
    case 'transform':
      return [...naming, ...getMappingIssues(node.fields)];
    case 'approval':
      return [
        ...naming,
        ...(node.slack && !(node.slack.account_id && node.slack.channel.trim())
          ? [{ code: 'slackIncomplete' as const }]
          : []),
        ...(node.summary.trim() ? [] : [{ code: 'summaryEmpty' as const }]),
        ...(node.window_seconds >= 1 && node.window_seconds <= MAX_APPROVAL_WINDOW_SECONDS
          ? []
          : [{ code: 'windowInvalid' as const }]),
      ];
    case 'wait':
      return [...naming, ...getWaitIssues(node)];
    case 'code':
      return node.sandbox_version_id ? naming : [...naming, { code: 'versionMissing' }];
    case 'agent_run':
      return [...naming, ...getAgentIssues(node)];
    case 'guardrail':
      return [...naming, ...getGuardrailIssues(node)];
    case 'loop':
      return [...naming, ...getLoopIssues(node, lookup)];
    default:
      return naming;
  }
}

export function isTriggerComplete(trigger: WorkflowTrigger) {
  switch (trigger.type) {
    case 'schedule':
      return isValidCron(trigger.cron);
    case 'event':
      return Boolean(trigger.event.trim());
    case 'service':
      return Boolean(trigger.integration && trigger.event && trigger.account_id);
    default:
      return true;
  }
}

/** Whether nothing the step runs after can skip the approval right before it. */
function isApprovedRightBefore(copy: WorkingCopy, node: WorkflowActionStep & { key: string }) {
  const approved = new Set<string>();
  const covers = (approval: WorkflowNode) =>
    approval.kind === 'approval' &&
    (approval.action_class === node.effect || approval.action_class === 'undeclared');

  for (const step of copy.nodes) {
    const incoming = copy.edges.filter((edge) => edge.to === step.key);
    const isGuarded =
      incoming.length > 0 &&
      incoming.every((edge) => {
        const from = copy.nodes.find((other) => other.key === edge.from);

        if (!from) {
          return false;
        }

        return (
          covers(from) ||
          ((from.kind === 'condition' || from.kind === 'transform') && approved.has(from.key))
        );
      });

    if (isGuarded) {
      approved.add(step.key);
    }
  }

  return approved.has(node.key);
}

function getMappedPaths(fields: WorkflowMappedField[]) {
  return fields.flatMap((field) => (field.from === 'input' ? [field.path] : []));
}

function getStepPaths(node: WorkflowNode) {
  switch (node.kind) {
    case 'action':
    case 'agent_run':
    case 'code':
      return getMappedPaths(node.inputs);
    case 'condition':
      return node.clauses.map((clause) => clause.path);
    case 'transform':
      return getMappedPaths(node.fields);
    case 'guardrail':
      return [node.text];
    case 'loop':
      return [node.over, ...getMappedPaths(node.inputs)];
    default:
      return [];
  }
}

export function isHighRiskAction(node: WorkflowNode) {
  return node.kind === 'action' && HIGH_RISK_EFFECTS.includes(node.effect);
}

/** What the browser can tell about publishing before asking. The server's answer decides. */
export function getPublishHints(
  copy: WorkingCopy,
  node: WorkflowNode,
  lookup: OperationLookup,
): StepIssue[] {
  const hints = getStepIssues(node, lookup);

  if (
    node.kind === 'action' &&
    isHighRiskAction(node) &&
    !isApprovedRightBefore(copy, node as WorkflowActionStep & { key: string })
  ) {
    hints.push({ code: 'approvalMissing' });
  }

  if (node.kind === 'action' && !lookup(node.integration, node.operation)) {
    hints.push({ code: 'operationGone' });
  }

  const before = getStepsBefore(copy.edges, node.key);
  const stray = getStepPaths(node).find((path) => {
    const root = path.split('.')[0];

    return root && root !== TRIGGER_KEY && !before.has(root);
  });

  if (stray) {
    hints.push({ code: 'readsLater', values: { path: stray } });
  }

  return hints;
}
