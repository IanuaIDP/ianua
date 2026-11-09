import {
  COMPANY_INTEGRATION,
  DATA_LEVELS,
} from '@/components/dashboard/workflows/builder/constants';
import { getStepsBefore } from '@/components/dashboard/workflows/builder/graph';
import type { WorkingCopy } from '@/components/dashboard/workflows/builder/working-copy';
import type { WorkflowNode, WorkflowActionStep } from '@/types/workflow-graph';

export type TouchVerb = 'admin' | 'anything' | 'changes' | 'messages' | 'reads';

export type TouchedPlace = { integration: string; level: string; verb: TouchVerb };

type ActionNode = WorkflowNode & WorkflowActionStep;

function isActionNode(node: WorkflowNode): node is ActionNode {
  return node.kind === 'action';
}

function getTouchVerb(effect: string): TouchVerb {
  switch (effect) {
    case 'read':
      return 'reads';
    case 'write':
      return 'changes';
    case 'communicate':
      return 'messages';
    case 'admin':
      return 'admin';
    default:
      return 'anything';
  }
}

function higherLevel(left: string, right: string) {
  return DATA_LEVELS.indexOf(right) > DATA_LEVELS.indexOf(left) ? right : left;
}

export function getTouchedPlaces(copy: WorkingCopy): TouchedPlace[] {
  const places = new Map<string, TouchedPlace>();

  for (const node of copy.nodes.filter(isActionNode)) {
    const verb = getTouchVerb(node.effect);
    const id = `${verb}/${node.integration}`;
    const held = places.get(id);

    places.set(id, {
      integration: node.integration,
      level: held ? higherLevel(held.level, node.ceiling) : node.ceiling,
      verb,
    });
  }

  return [...places.values()];
}

/** The most sensitive data each step can be holding, from what was read up to it. */
export function getFlowLevels(copy: WorkingCopy) {
  const levels: Record<string, string> = {};

  for (const node of copy.nodes) {
    const before = [...getStepsBefore(copy.edges, node.key), node.key]
      .map((key) => copy.nodes.find((other) => other.key === key))
      .filter((step): step is WorkflowNode => Boolean(step));

    levels[node.key] = before
      .filter(isActionNode)
      .filter((step) => step.effect === 'read')
      .reduce((level, step) => higherLevel(level, step.ceiling), 'public');
  }

  return levels;
}

/** Steps that send outside the company after a step read confidential data. */
export function getLeakingSteps(copy: WorkingCopy): ActionNode[] {
  const levels = getFlowLevels(copy);

  return copy.nodes
    .filter(isActionNode)
    .filter(
      (node) =>
        node.integration !== COMPANY_INTEGRATION &&
        (node.effect === 'communicate' || node.effect === 'write') &&
        DATA_LEVELS.indexOf(levels[node.key]) >= DATA_LEVELS.indexOf('confidential'),
    );
}

export function getOutsideIntegrations(copy: WorkingCopy) {
  return [
    ...new Set(
      copy.nodes
        .filter(isActionNode)
        .filter((node) => node.integration !== COMPANY_INTEGRATION)
        .map((node) => node.integration),
    ),
  ];
}
