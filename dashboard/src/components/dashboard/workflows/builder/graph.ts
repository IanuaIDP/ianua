import { TRIGGER_KEY } from '@/components/dashboard/workflows/builder/constants';
import type { WorkflowEdge, WorkflowNode, WorkflowPort } from '@/types/workflow-graph';

export function getStepPorts(node: WorkflowNode): WorkflowPort[] {
  return node.kind === 'condition' ? ['when_true', 'when_false'] : ['next'];
}

export function getStepsReachableFrom(edges: WorkflowEdge[], start: string) {
  const reached = new Set<string>();
  const queue = [start];

  while (queue.length > 0) {
    const key = queue.shift();

    for (const edge of edges) {
      if (edge.from === key && !reached.has(edge.to)) {
        reached.add(edge.to);
        queue.push(edge.to);
      }
    }
  }

  return reached;
}

/** Every step that can come before `key`, the only ones it may read. */
export function getStepsBefore(edges: WorkflowEdge[], key: string) {
  const before = new Set<string>();
  const queue = [key];

  while (queue.length > 0) {
    const current = queue.shift();

    for (const edge of edges) {
      if (edge.to === current && !before.has(edge.from)) {
        before.add(edge.from);
        queue.push(edge.from);
      }
    }
  }

  return before;
}

export function wouldMakeCircle(edges: WorkflowEdge[], from: string, to: string) {
  return from === to || getStepsReachableFrom(edges, to).has(from);
}

/** Steps with no arrow into them, which start as soon as the trigger fires. */
export function getFirstSteps(nodes: WorkflowNode[], edges: WorkflowEdge[]) {
  const led = new Set(edges.map((edge) => edge.to));

  return nodes.filter((node) => !led.has(node.key));
}

/** Each step after every step with an arrow into it; a tie goes in the given order. */
export function getStepsInOrder(nodes: WorkflowNode[], edges: WorkflowEdge[]) {
  const waiting = new Map(nodes.map((node) => [node.key, 0]));

  for (const edge of edges) {
    waiting.set(edge.to, (waiting.get(edge.to) ?? 0) + 1);
  }

  const order: WorkflowNode[] = [];
  const remaining = [...nodes];

  while (remaining.length > 0) {
    const index = remaining.findIndex((node) => waiting.get(node.key) === 0);
    const [next] = remaining.splice(Math.max(index, 0), 1);

    order.push(next);

    for (const edge of edges) {
      if (edge.from === next.key) {
        waiting.set(edge.to, (waiting.get(edge.to) ?? 0) - 1);
      }
    }
  }

  return order;
}

function slugify(name: string) {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 58);
}

/** A key from the step's first name. Later steps read it by key, so it never changes. */
export function makeStepKey(name: string, fallback: string, taken: Iterable<string>) {
  const used = new Set(taken);
  const base = slugify(name) || fallback;
  const start = base === TRIGGER_KEY ? `${TRIGGER_KEY}-step` : base;

  if (!used.has(start)) {
    return start;
  }

  let number = 2;

  while (used.has(`${start}-${number}`)) {
    number += 1;
  }

  return `${start}-${number}`;
}

/** Whether two JSON values hold the same data, whatever order their keys came in. */
export function isSameJson(left: unknown, right: unknown) {
  return JSON.stringify(sortKeys(left)) === JSON.stringify(sortKeys(right));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, sortKeys(item)]),
    );
  }

  return value;
}
