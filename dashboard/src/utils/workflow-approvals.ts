import type { WorkflowApprovalStep, WorkflowGraph, WorkflowNode } from '@/types/workflow-graph';

/** The action classes that need two different people, each with a fresh code. */
const TWO_PERSON_CLASSES = new Set(['undeclared', 'delete', 'configure', 'financial', 'admin']);

/** Whether an approval of this action class needs two people. Mirrors the API's rule. */
export function needsTwoApprovers(actionClass: string) {
  return TWO_PERSON_CLASSES.has(actionClass);
}

function findNode(graph: WorkflowGraph, key: string): WorkflowNode | null {
  for (const node of graph.nodes) {
    if (node.key === key) {
      return node;
    }

    if (node.kind === 'loop') {
      const inner = findNode(node.steps, key);

      if (inner) {
        return inner;
      }
    }
  }

  return null;
}

export type ApprovalStepDetail = {
  actionClass: string;
  name: string;
  summary: string;
};

/** The approval step named `key`, searching inside loops too. */
export function findApprovalStep(graph: WorkflowGraph, key: string): ApprovalStepDetail | null {
  const node = findNode(graph, key);

  if (!node || node.kind !== 'approval') {
    return null;
  }

  const step: WorkflowApprovalStep = node;

  return { actionClass: step.action_class, name: node.name, summary: step.summary };
}
