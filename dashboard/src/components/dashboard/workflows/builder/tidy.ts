import {
  CARD_HEIGHT,
  CARD_WIDTH,
  COLUMN_SPACING,
  GRID_SIZE,
  ROW_SPACING,
} from '@/components/dashboard/workflows/builder/constants';
import { getStepsInOrder } from '@/components/dashboard/workflows/builder/graph';
import type { Positions, StepSize } from '@/components/dashboard/workflows/builder/working-copy';
import type { WorkflowEdge, WorkflowNode } from '@/types/workflow-graph';

const LEFT_EDGE = COLUMN_SPACING + 60;
const TOP_EDGE = 60;

function getColumns(nodes: WorkflowNode[], edges: WorkflowEdge[]) {
  const columnOf = new Map<string, number>();

  for (const node of getStepsInOrder(nodes, edges)) {
    const before = edges
      .filter((edge) => edge.to === node.key)
      .map((edge) => columnOf.get(edge.from) ?? 0);

    columnOf.set(node.key, before.length > 0 ? Math.max(...before) + 1 : 0);
  }

  return columnOf;
}

function snap(value: number) {
  return Math.round(value / GRID_SIZE) * GRID_SIZE;
}

function getParentPull(key: string, edges: WorkflowEdge[], placed: Positions) {
  const pulls = edges
    .filter((edge) => edge.to === key && placed[edge.from])
    .map((edge) => placed[edge.from].y + (edge.port === 'when_true' ? -1 : 0));

  return pulls.length > 0 ? pulls.reduce((sum, y) => sum + y, 0) / pulls.length : 0;
}

/** Lines steps up in columns: each column holds the steps one arrow further on. */
export function tidyPositions(
  nodes: WorkflowNode[],
  edges: WorkflowEdge[],
  sizeOf: (node: WorkflowNode) => StepSize,
  origin: { x: number; y: number } = { x: LEFT_EDGE, y: TOP_EDGE },
) {
  const columnOf = getColumns(nodes, edges);
  const placed: Positions = {};
  const last = nodes.reduce((most, node) => Math.max(most, columnOf.get(node.key) ?? 0), 0);
  let x = origin.x;

  for (let column = 0; column <= last; column += 1) {
    const inColumn = nodes
      .filter((node) => (columnOf.get(node.key) ?? 0) === column)
      .sort(
        (left, right) =>
          getParentPull(left.key, edges, placed) - getParentPull(right.key, edges, placed),
      );
    let nextFree = origin.y;
    let widest = CARD_WIDTH;

    for (const node of inColumn) {
      const size = sizeOf(node);
      const pull = getParentPull(node.key, edges, placed);
      const y = Math.max(nextFree, pull);

      placed[node.key] = { x: snap(x), y: snap(y) };
      nextFree = snap(y) + size.height + (ROW_SPACING - CARD_HEIGHT);
      widest = Math.max(widest, size.width);
    }

    x += widest + (COLUMN_SPACING - CARD_WIDTH);
  }

  return placed;
}
