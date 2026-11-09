import {
  CARD_HEIGHT,
  CARD_WIDTH,
  COLUMN_SPACING,
  PORT_OFFSET_Y,
  TRIGGER_KEY,
} from '@/components/dashboard/workflows/builder/constants';
import { getFirstSteps } from '@/components/dashboard/workflows/builder/graph';
import {
  getLoopLayout,
  getStepSize,
  type Point,
  type WorkingCopy,
} from '@/components/dashboard/workflows/builder/working-copy';
import type { WorkflowEdge, WorkflowNode, WorkflowPort } from '@/types/workflow-graph';

export type SceneCard = {
  height: number;
  inLoop: string | null;
  key: string;
  node: WorkflowNode | null;
  width: number;
  x: number;
  y: number;
};

export type SceneWire = {
  edge: WorkflowEdge;
  id: string;
  isImplied: boolean;
  middle: Point;
  path: string;
};

export type CanvasScene = {
  bounds: { bottom: number; left: number; right: number; top: number };
  cards: SceneCard[];
  loops: SceneCard[];
  wires: SceneWire[];
};

function toPath(from: Point, to: Point) {
  const bend = Math.max(50, Math.abs(to.x - from.x) / 2);

  return `M${from.x},${from.y} C${from.x + bend},${from.y} ${to.x - bend},${to.y} ${to.x},${to.y}`;
}

function getOutPoint(card: SceneCard, port: WorkflowPort): Point {
  return { x: card.x + card.width + 4, y: card.y + PORT_OFFSET_Y[port] };
}

function getInPoint(card: SceneCard): Point {
  return { x: card.x - 6, y: card.y + PORT_OFFSET_Y.next };
}

function toWire(edge: WorkflowEdge, from: SceneCard, to: SceneCard, isImplied: boolean): SceneWire {
  const start = getOutPoint(from, edge.port);
  const end = getInPoint(to);

  return {
    edge,
    id: `${edge.from}/${edge.port}/${edge.to}`,
    isImplied,
    middle: { x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 },
    path: toPath(start, end),
  };
}

function getTriggerCard(copy: WorkingCopy): SceneCard {
  const first = getFirstSteps(copy.nodes, copy.edges);
  const points = copy.nodes.map((node) => copy.positions[node.key]).filter(Boolean);
  const left = points.length > 0 ? Math.min(...points.map((point) => point.x)) : 360;
  const rootPoints = first.map((node) => copy.positions[node.key]).filter(Boolean);
  const y =
    rootPoints.length > 0
      ? rootPoints.reduce((sum, point) => sum + point.y, 0) / rootPoints.length
      : 60;

  return {
    height: CARD_HEIGHT,
    inLoop: null,
    key: TRIGGER_KEY,
    node: null,
    width: CARD_WIDTH,
    x: left - COLUMN_SPACING,
    y,
  };
}

function getLoopCards(node: Extract<WorkflowNode, { kind: 'loop' }>, card: SceneCard) {
  const layout = getLoopLayout(node);
  const inner: SceneCard[] = node.steps.nodes.map((step) => ({
    height: CARD_HEIGHT,
    inLoop: node.key,
    key: step.key,
    node: step,
    width: CARD_WIDTH,
    x: card.x + layout.positions[step.key].x,
    y: card.y + layout.positions[step.key].y,
  }));
  const byKey = new Map(inner.map((step) => [step.key, step]));
  const wires = node.steps.edges.flatMap((edge) => {
    const from = byKey.get(edge.from);
    const to = byKey.get(edge.to);

    return from && to ? [toWire(edge, from, to, false)] : [];
  });

  return { inner, wires };
}

/** Where everything sits, from the working copy alone. */
export function buildCanvasScene(copy: WorkingCopy): CanvasScene {
  const trigger = getTriggerCard(copy);
  const cards: SceneCard[] = [trigger];
  const loops: SceneCard[] = [];
  const wires: SceneWire[] = [];
  const byKey = new Map<string, SceneCard>();

  for (const node of copy.nodes) {
    const point = copy.positions[node.key] ?? { x: 0, y: 0 };
    const size = getStepSize(node);
    const card: SceneCard = { ...size, inLoop: null, key: node.key, node, ...point };

    byKey.set(node.key, card);

    if (node.kind !== 'loop') {
      cards.push(card);
      continue;
    }

    const { inner, wires: innerWires } = getLoopCards(node, card);

    loops.push(card);
    cards.push(...inner);
    wires.push(...innerWires);
  }

  for (const edge of copy.edges) {
    const from = byKey.get(edge.from);
    const to = byKey.get(edge.to);

    if (from && to) {
      wires.push(toWire(edge, from, to, false));
    }
  }

  for (const node of getFirstSteps(copy.nodes, copy.edges)) {
    const to = byKey.get(node.key);

    if (to) {
      wires.push(toWire({ from: TRIGGER_KEY, port: 'next', to: node.key }, trigger, to, true));
    }
  }

  const all = [...cards, ...loops];

  return {
    bounds: {
      bottom: Math.max(...all.map((card) => card.y + card.height)),
      left: Math.min(...all.map((card) => card.x)),
      right: Math.max(...all.map((card) => card.x + card.width)),
      top: Math.min(...all.map((card) => card.y)),
    },
    cards,
    loops,
    wires,
  };
}
