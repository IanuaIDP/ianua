import {
  EMPTY_DRAFT_KEY,
  EMPTY_DRAFT_NAME,
} from '@/components/dashboard/workflows/builder/constants';
import { isSameJson } from '@/components/dashboard/workflows/builder/graph';
import {
  getStepIssues,
  isTriggerComplete,
  type OperationLookup,
} from '@/components/dashboard/workflows/builder/step-issues';
import {
  toStepPositions,
  type Positions,
  type WorkingCopy,
} from '@/components/dashboard/workflows/builder/working-copy';
import type {
  WorkflowEdge,
  WorkflowGraph,
  NewWorkflow,
  WorkflowNode,
  WorkflowDraftEdit,
} from '@/types/workflow-graph';

/** What the server holds, as last sent or read. */
export type SavedCopy = {
  description: string;
  failureAlert: WorkingCopy['failureAlert'];
  graph: WorkflowGraph;
  name: string;
  positions: Positions;
  runLimitSeconds: number;
  trigger: WorkingCopy['trigger'];
};

function getSendableKeys(nodes: WorkflowNode[], saved: SavedCopy | null, lookup: OperationLookup) {
  const sendable = new Set<string>();

  for (const node of nodes) {
    const held = saved?.graph.nodes.find((other) => other.key === node.key);

    if (getStepIssues(node, lookup).length === 0 || (held && isSameJson(held, node))) {
      sendable.add(node.key);
    }
  }

  return sendable;
}

/** Arrows with the steps not sent taken out, so what follows one still comes after what led to it. */
function getSendableEdges(edges: WorkflowEdge[], sendable: Set<string>) {
  const result: WorkflowEdge[] = [];
  const add = (edge: WorkflowEdge) => {
    if (
      !result.some(
        (other) => other.from === edge.from && other.port === edge.port && other.to === edge.to,
      )
    ) {
      result.push(edge);
    }
  };

  function follow(from: string, port: WorkflowEdge['port'], to: string, seen: Set<string>) {
    if (sendable.has(to)) {
      add({ from, port, to });

      return;
    }

    if (seen.has(to)) {
      return;
    }

    seen.add(to);

    for (const edge of edges) {
      if (edge.from === to) {
        follow(from, port, edge.to, seen);
      }
    }
  }

  for (const edge of edges) {
    if (sendable.has(edge.from)) {
      follow(edge.from, edge.port, edge.to, new Set());
    }
  }

  return result;
}

export function getSendableGraph(
  copy: WorkingCopy,
  saved: SavedCopy | null,
  lookup: OperationLookup,
) {
  const sendable = getSendableKeys(copy.nodes, saved, lookup);
  const graph: WorkflowGraph = {
    edges: getSendableEdges(copy.edges, sendable),
    nodes: copy.nodes.filter((node) => sendable.has(node.key)),
  };

  return {
    graph,
    layout: toStepPositions(copy.positions, [...sendable]),
    unsent: copy.nodes.filter((node) => !sendable.has(node.key)),
  };
}

/** What is sent while a draft has no step the server would take. */
const EMPTY_DRAFT_GRAPH: WorkflowGraph = {
  edges: [],
  nodes: [
    {
      fields: [],
      key: EMPTY_DRAFT_KEY,
      kind: 'transform',
      name: EMPTY_DRAFT_NAME,
    },
  ],
};

/** The body of the first save, or nothing while it cannot be made. */
export function toNewWorkflow(
  copy: WorkingCopy,
  lookup: OperationLookup,
  { allowEmpty, isCatalogReady }: { allowEmpty: boolean; isCatalogReady: boolean },
): NewWorkflow | null {
  const { graph, layout } = isCatalogReady
    ? getSendableGraph(copy, null, lookup)
    : { graph: { edges: [], nodes: [] }, layout: [] };
  const hasSteps = graph.nodes.length > 0;

  if ((!hasSteps && !allowEmpty) || !copy.name.trim() || !isTriggerComplete(copy.trigger)) {
    return null;
  }

  return {
    description: copy.description.trim() || undefined,
    failure_alert: copy.failureAlert,
    graph: hasSteps ? graph : EMPTY_DRAFT_GRAPH,
    layout,
    name: copy.name.trim(),
    run_limit_seconds: copy.runLimitSeconds,
    trigger: copy.trigger,
  };
}

/** The edits that bring the server to this copy, each one a separate call. */
export function getDraftEdits(
  copy: WorkingCopy,
  saved: SavedCopy,
  lookup: OperationLookup,
): { edit: WorkflowDraftEdit; next: Partial<SavedCopy> }[] {
  const { graph, layout } = getSendableGraph(copy, saved, lookup);
  const edits: { edit: WorkflowDraftEdit; next: Partial<SavedCopy> }[] = [];
  const name = copy.name.trim();
  const description = copy.description.trim();

  if (name && name !== saved.name) {
    edits.push({ edit: { edit: 'rename', name }, next: { name } });
  }

  if (description !== saved.description) {
    edits.push({
      edit: { description: description || null, edit: 'describe' },
      next: { description },
    });
  }

  if (copy.runLimitSeconds !== saved.runLimitSeconds) {
    edits.push({
      edit: { edit: 'change_run_limit', run_limit_seconds: copy.runLimitSeconds },
      next: { runLimitSeconds: copy.runLimitSeconds },
    });
  }

  if (copy.failureAlert !== saved.failureAlert) {
    edits.push({
      edit: { edit: 'change_failure_alert', failure_alert: copy.failureAlert },
      next: { failureAlert: copy.failureAlert },
    });
  }

  if (isTriggerComplete(copy.trigger) && !isSameJson(copy.trigger, saved.trigger)) {
    edits.push({
      edit: { edit: 'change_trigger', trigger: copy.trigger },
      next: { trigger: copy.trigger },
    });
  }

  if (!isSameJson(graph, saved.graph)) {
    edits.push({
      edit: { edit: 'replace_steps', graph: graph.nodes.length > 0 ? graph : EMPTY_DRAFT_GRAPH },
      next: { graph },
    });
  }

  const positions = Object.fromEntries(
    layout.map((position) => [position.key, { x: position.x, y: position.y }]),
  );

  if (graph.nodes.length > 0 && !isSameJson(positions, saved.positions)) {
    edits.push({ edit: { edit: 'arrange', layout }, next: { positions } });
  }

  return edits;
}

/** Whether anything in the copy is not on the server yet. */
export function hasUnsavedChanges(
  copy: WorkingCopy,
  saved: SavedCopy | null,
  lookup: OperationLookup,
) {
  if (!saved) {
    return true;
  }

  return (
    getDraftEdits(copy, saved, lookup).length > 0 ||
    getSendableGraph(copy, saved, lookup).unsent.length > 0
  );
}
