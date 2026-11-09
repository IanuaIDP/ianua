import {
  CARD_HEIGHT,
  CARD_WIDTH,
  COLUMN_SPACING,
  GRID_SIZE,
  LOOP_HEADER_HEIGHT,
  LOOP_PADDING,
  MAX_POINT,
  ROW_SPACING,
  EMPTY_DRAFT_KEY,
  TRIGGER_KEY,
} from '@/components/dashboard/workflows/builder/constants';
import {
  getStepsReachableFrom,
  makeStepKey,
  wouldMakeCircle,
} from '@/components/dashboard/workflows/builder/graph';
import { tidyPositions } from '@/components/dashboard/workflows/builder/tidy';
import type {
  WorkflowEdge,
  WorkflowNode,
  WorkflowStepPosition,
  WorkflowTrigger,
  WorkflowFailureAlert,
  WorkflowPort,
} from '@/types/workflow-graph';
import type { Workflow } from '@/types/workflows';

export type Point = { x: number; y: number };
export type Positions = Record<string, Point>;
export type StepSize = { height: number; width: number };

/** The open draft as the person sees it, which may hold steps not filled in yet. */
export type WorkingCopy = {
  description: string;
  edges: WorkflowEdge[];
  failureAlert: WorkflowFailureAlert;
  name: string;
  nodes: WorkflowNode[];
  positions: Positions;
  runLimitSeconds: number;
  trigger: WorkflowTrigger;
};

/** Where a new step goes: after a step's way out, or onto an arrow. */
export type StepPlacement =
  { after: string; port: WorkflowPort; to?: string } | { at: Point } | { intoLoop: string };

export function getStepSize(node: WorkflowNode): StepSize {
  if (node.kind !== 'loop') {
    return { height: CARD_HEIGHT, width: CARD_WIDTH };
  }

  const inner = getLoopLayout(node);

  return { height: inner.height, width: inner.width };
}

export function getLoopLayout(node: Extract<WorkflowNode, { kind: 'loop' }>) {
  const positions = tidyPositions(
    node.steps.nodes,
    node.steps.edges,
    () => ({ height: CARD_HEIGHT, width: CARD_WIDTH }),
    { x: LOOP_PADDING, y: LOOP_HEADER_HEIGHT },
  );
  const points = Object.values(positions);
  const right = points.reduce((most, point) => Math.max(most, point.x + CARD_WIDTH), CARD_WIDTH);
  const bottom = points.reduce(
    (most, point) => Math.max(most, point.y + CARD_HEIGHT),
    LOOP_HEADER_HEIGHT + CARD_HEIGHT,
  );

  return { height: bottom + LOOP_PADDING, positions, width: right + LOOP_PADDING };
}

export function toWorkingCopy(workflow: Workflow): WorkingCopy {
  const placed = Object.fromEntries(
    workflow.layout.map((position) => [position.key, { x: position.x, y: position.y }]),
  );
  const nodes = workflow.graph.nodes.filter((node) => node.key !== EMPTY_DRAFT_KEY);
  const edges = workflow.graph.edges.filter(
    (edge) => edge.from !== EMPTY_DRAFT_KEY && edge.to !== EMPTY_DRAFT_KEY,
  );
  const tidied = tidyPositions(nodes, edges, getStepSize);
  const positions = Object.fromEntries(
    nodes.map((node) => [node.key, placed[node.key] ?? tidied[node.key]]),
  );

  return {
    description: workflow.description ?? '',
    edges,
    failureAlert: workflow.failureAlert as WorkflowFailureAlert,
    name: workflow.name,
    nodes,
    positions,
    runLimitSeconds: workflow.runLimitSeconds,
    trigger: workflow.trigger,
  };
}

export function toStepPositions(positions: Positions, keys: string[]): WorkflowStepPosition[] {
  return keys
    .filter((key) => positions[key])
    .map((key) => ({ key, x: positions[key].x, y: positions[key].y }));
}

function snapPoint(value: number) {
  const snapped = Math.round(value / GRID_SIZE) * GRID_SIZE;

  return Math.max(0, Math.min(MAX_POINT, snapped));
}

export function snapToGrid(point: Point): Point {
  return { x: snapPoint(point.x), y: snapPoint(point.y) };
}

function findFreeSpot(copy: WorkingCopy, wanted: Point) {
  const isBusy = (point: Point) =>
    Object.values(copy.positions).some(
      (other) =>
        Math.abs(other.x - point.x) < CARD_WIDTH + GRID_SIZE &&
        Math.abs(other.y - point.y) < CARD_HEIGHT + GRID_SIZE,
    );
  let spot = snapToGrid(wanted);

  for (let tries = 0; isBusy(spot) && tries < 60; tries += 1) {
    spot = snapToGrid({ x: spot.x, y: spot.y + 40 });
  }

  return spot;
}

function getPlacedAfter(copy: WorkingCopy, placement: { after: string; port: WorkflowPort }) {
  const from = copy.positions[placement.after];

  if (!from) {
    return { x: COLUMN_SPACING + 60, y: 60 };
  }

  const offset =
    placement.port === 'when_true'
      ? -ROW_SPACING / 2
      : placement.port === 'when_false'
        ? ROW_SPACING / 2
        : 0;

  return { x: from.x + COLUMN_SPACING, y: from.y + offset };
}

function insertAfter(
  copy: WorkingCopy,
  node: WorkflowNode,
  placement: { after: string; port: WorkflowPort; to?: string },
): WorkingCopy {
  const isTaken = (edge: WorkflowEdge) =>
    edge.from === placement.after &&
    edge.port === placement.port &&
    (!placement.to || edge.to === placement.to);
  const fromTrigger = placement.after === TRIGGER_KEY;
  const moved = fromTrigger && placement.to ? [placement.to] : [];
  const taken = fromTrigger ? [] : copy.edges.filter(isTaken);
  const nextKeys = [...moved, ...taken.map((edge) => edge.to)];
  const downstream = new Set<string>(nextKeys);

  for (const key of nextKeys) {
    getStepsReachableFrom(copy.edges, key).forEach((later) => downstream.add(later));
  }

  const positions = Object.fromEntries(
    Object.entries(copy.positions).map(([key, point]) => [
      key,
      downstream.has(key) ? snapToGrid({ x: point.x + COLUMN_SPACING, y: point.y }) : point,
    ]),
  );
  const target = placement.to ? copy.positions[placement.to] : undefined;
  const spot = findFreeSpot({ ...copy, positions }, target ?? getPlacedAfter(copy, placement));
  const kept = fromTrigger ? copy.edges : copy.edges.filter((edge) => !isTaken(edge));
  const entry: WorkflowEdge[] = fromTrigger
    ? []
    : [{ from: placement.after, port: placement.port, to: node.key }];
  const exits: WorkflowEdge[] = nextKeys.map((to) => ({ from: node.key, port: 'next', to }));

  return {
    ...copy,
    edges: [...kept, ...entry, ...exits],
    nodes: [...copy.nodes, node],
    positions: { ...positions, [node.key]: spot },
  };
}

function insertInLoop(
  copy: WorkingCopy,
  loopKey: string,
  node: WorkflowNode,
  placement: { after: string; port: WorkflowPort; to?: string },
): WorkingCopy {
  const isTaken = (edge: WorkflowEdge) =>
    edge.from === placement.after &&
    edge.port === placement.port &&
    (!placement.to || edge.to === placement.to);

  return changeLoop(copy, loopKey, (graph) => ({
    edges: [
      ...graph.edges.filter((edge) => !isTaken(edge)),
      { from: placement.after, port: placement.port, to: node.key },
      ...graph.edges
        .filter(isTaken)
        .map((edge): WorkflowEdge => ({ from: node.key, port: 'next', to: edge.to })),
    ],
    nodes: [...graph.nodes, node],
  }));
}

function appendToLoop(copy: WorkingCopy, loopKey: string, node: WorkflowNode): WorkingCopy {
  return changeLoop(copy, loopKey, (graph) => {
    const last = graph.nodes[graph.nodes.length - 1];
    const canFollow =
      last && last.kind !== 'condition' && !graph.edges.some((edge) => edge.from === last.key);

    return {
      edges: canFollow
        ? [...graph.edges, { from: last.key, port: 'next', to: node.key }]
        : graph.edges,
      nodes: [...graph.nodes, node],
    };
  });
}

export function addStep(
  copy: WorkingCopy,
  node: WorkflowNode,
  placement: StepPlacement,
): WorkingCopy {
  if ('intoLoop' in placement) {
    return appendToLoop(copy, placement.intoLoop, node);
  }

  if ('after' in placement) {
    const loop = findLoopOf(copy.nodes, placement.after);

    return loop
      ? insertInLoop(copy, loop.key, node, placement)
      : insertAfter(copy, node, placement);
  }

  return {
    ...copy,
    nodes: [...copy.nodes, node],
    positions: { ...copy.positions, [node.key]: findFreeSpot(copy, placement.at) },
  };
}

type StepGraph = { edges: WorkflowEdge[]; nodes: WorkflowNode[] };

type LoopNode = Extract<WorkflowNode, { kind: 'loop' }>;

export function findStep(nodes: WorkflowNode[], key: string): WorkflowNode | null {
  for (const node of nodes) {
    if (node.key === key) {
      return node;
    }

    if (node.kind === 'loop') {
      const inner = findStep(node.steps.nodes, key);

      if (inner) {
        return inner;
      }
    }
  }

  return null;
}

/** The loop holding a step, or nothing for a step on the board itself. */
export function findLoopOf(nodes: WorkflowNode[], key: string): LoopNode | null {
  const loops = nodes.filter((node): node is LoopNode => node.kind === 'loop');

  return loops.find((loop) => loop.steps.nodes.some((node) => node.key === key)) ?? null;
}

function changeLoop(
  copy: WorkingCopy,
  loopKey: string,
  recipe: (graph: StepGraph) => StepGraph,
): WorkingCopy {
  return {
    ...copy,
    nodes: copy.nodes.map((node) =>
      node.kind === 'loop' && node.key === loopKey ? { ...node, steps: recipe(node.steps) } : node,
    ),
  };
}

function removeFromGraph(graph: StepGraph, key: string): StepGraph {
  const into = graph.edges.filter((edge) => edge.to === key);
  const out = graph.edges.filter((edge) => edge.from === key);
  const remaining = graph.edges.filter((edge) => edge.from !== key && edge.to !== key);
  const bridged =
    out.length === 1
      ? into
          .map((edge) => ({ ...edge, to: out[0].to }))
          .filter(
            (edge) =>
              !remaining.some(
                (other) =>
                  other.from === edge.from && other.port === edge.port && other.to === edge.to,
              ),
          )
      : [];

  return {
    edges: [...remaining, ...bridged],
    nodes: graph.nodes.filter((node) => node.key !== key),
  };
}

/** Takes a step out; when one way led on from it, what led to it leads there now. */
export function removeStep(copy: WorkingCopy, key: string): WorkingCopy {
  const loop = findLoopOf(copy.nodes, key);

  if (loop) {
    return changeLoop(copy, loop.key, (graph) => removeFromGraph(graph, key));
  }

  const positions = { ...copy.positions };

  delete positions[key];

  return { ...copy, ...removeFromGraph(copy, key), positions };
}

function getGraphOf(copy: WorkingCopy, key: string): StepGraph {
  return findLoopOf(copy.nodes, key)?.steps ?? copy;
}

function hasEdge(edges: WorkflowEdge[], edge: WorkflowEdge) {
  return edges.some(
    (other) => other.from === edge.from && other.port === edge.port && other.to === edge.to,
  );
}

export function connectSteps(copy: WorkingCopy, edge: WorkflowEdge): WorkingCopy {
  const loop = findLoopOf(copy.nodes, edge.from);

  if (loop) {
    return changeLoop(copy, loop.key, (graph) => ({ ...graph, edges: [...graph.edges, edge] }));
  }

  return { ...copy, edges: [...copy.edges, edge] };
}

export function canConnectSteps(copy: WorkingCopy, edge: WorkflowEdge) {
  const graph = getGraphOf(copy, edge.from);

  return (
    graph.nodes.some((node) => node.key === edge.to) &&
    !hasEdge(graph.edges, edge) &&
    !wouldMakeCircle(graph.edges, edge.from, edge.to)
  );
}

export function isExistingEdge(copy: WorkingCopy, edge: WorkflowEdge) {
  return hasEdge(getGraphOf(copy, edge.from).edges, edge);
}

export function disconnectSteps(copy: WorkingCopy, edge: WorkflowEdge): WorkingCopy {
  const without = (graph: StepGraph) => ({
    ...graph,
    edges: graph.edges.filter(
      (other) => !(other.from === edge.from && other.port === edge.port && other.to === edge.to),
    ),
  });
  const loop = findLoopOf(copy.nodes, edge.from);

  return loop ? changeLoop(copy, loop.key, without) : { ...copy, ...without(copy) };
}

function addApprovalInGraph(graph: StepGraph, approval: WorkflowNode, key: string): StepGraph {
  return {
    edges: [
      ...graph.edges.filter((edge) => edge.to !== key),
      ...graph.edges
        .filter((edge) => edge.to === key)
        .map((edge) => ({ ...edge, to: approval.key })),
      { from: approval.key, port: 'next', to: key },
    ],
    nodes: [...graph.nodes, approval],
  };
}

/** Puts an approval right before `key`, taking over every arrow into it. */
export function addApprovalBefore(
  copy: WorkingCopy,
  approval: WorkflowNode,
  key: string,
): WorkingCopy {
  const loop = findLoopOf(copy.nodes, key);

  if (loop) {
    return changeLoop(copy, loop.key, (graph) => addApprovalInGraph(graph, approval, key));
  }

  const point = copy.positions[key] ?? { x: COLUMN_SPACING, y: 60 };
  const shifted = new Set<string>([key, ...getStepsReachableFrom(copy.edges, key)]);
  const positions = Object.fromEntries(
    Object.entries(copy.positions).map(([other, value]) => [
      other,
      shifted.has(other) ? snapToGrid({ x: value.x + COLUMN_SPACING, y: value.y }) : value,
    ]),
  );

  return {
    ...copy,
    ...addApprovalInGraph(copy, approval, key),
    positions: { ...positions, [approval.key]: point },
  };
}

function updateIn(
  nodes: WorkflowNode[],
  key: string,
  recipe: (node: WorkflowNode) => WorkflowNode,
): WorkflowNode[] {
  return nodes.map((node) => {
    if (node.key === key) {
      return recipe(node);
    }

    return node.kind === 'loop'
      ? { ...node, steps: { ...node.steps, nodes: updateIn(node.steps.nodes, key, recipe) } }
      : node;
  });
}

export function updateStep(
  copy: WorkingCopy,
  key: string,
  recipe: (node: WorkflowNode) => WorkflowNode,
): WorkingCopy {
  return { ...copy, nodes: updateIn(copy.nodes, key, recipe) };
}

export function moveStep(copy: WorkingCopy, key: string, point: Point): WorkingCopy {
  return { ...copy, positions: { ...copy.positions, [key]: snapToGrid(point) } };
}

export function tidyWorkingCopy(copy: WorkingCopy): WorkingCopy {
  return { ...copy, positions: tidyPositions(copy.nodes, copy.edges, getStepSize) };
}

export function getAllStepKeys(nodes: WorkflowNode[]): string[] {
  return nodes.flatMap((node) =>
    node.kind === 'loop' ? [node.key, ...getAllStepKeys(node.steps.nodes)] : [node.key],
  );
}

export function makeNodeKey(copy: WorkingCopy, name: string, fallback: string) {
  return makeStepKey(name, fallback, [...getAllStepKeys(copy.nodes), TRIGGER_KEY]);
}

/** Whether a step is the entry of its loop, the only place one approval for every item may sit. */
export function isLoopEntry(loop: LoopNode, key: string) {
  return !loop.steps.edges.some((edge) => edge.to === key);
}
