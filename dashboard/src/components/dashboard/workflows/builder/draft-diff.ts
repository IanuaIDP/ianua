import { isSameJson } from '@/components/dashboard/workflows/builder/graph';
import type { WorkingCopy } from '@/components/dashboard/workflows/builder/working-copy';
import type { WorkflowEdge, WorkflowGraph, WorkflowTrigger } from '@/types/workflow-graph';

export type DraftChange =
  | { kind: 'add'; name: string }
  | { from: string; kind: 'rename'; to: string }
  | { kind: 'edit'; name: string }
  | { kind: 'remove'; name: string }
  | { from: string; kind: 'follow'; to: string }
  | { kind: 'trigger' };

function hasEdge(edges: WorkflowEdge[], edge: WorkflowEdge) {
  return edges.some(
    (other) => other.from === edge.from && other.port === edge.port && other.to === edge.to,
  );
}

/** What the next run does differently, compared with the version in service. */
export function getDraftChanges(
  copy: WorkingCopy,
  inService: { graph: WorkflowGraph; trigger: WorkflowTrigger } | null,
): DraftChange[] {
  if (!inService) {
    return copy.nodes.map((node) => ({ kind: 'add', name: node.name }));
  }

  const was = new Map(inService.graph.nodes.map((node) => [node.key, node]));
  const changes: DraftChange[] = [];

  if (!isSameJson(copy.trigger, inService.trigger)) {
    changes.push({ kind: 'trigger' });
  }

  for (const node of copy.nodes) {
    const old = was.get(node.key);

    if (!old) {
      changes.push({ kind: 'add', name: node.name });
      continue;
    }

    if (old.name !== node.name) {
      changes.push({ from: old.name, kind: 'rename', to: node.name });
    }

    if (!isSameJson({ ...old, name: '' }, { ...node, name: '' })) {
      changes.push({ kind: 'edit', name: node.name });
    }
  }

  for (const node of inService.graph.nodes) {
    if (!copy.nodes.some((other) => other.key === node.key)) {
      changes.push({ kind: 'remove', name: node.name });
    }
  }

  const byKey = new Map(copy.nodes.map((node) => [node.key, node.name]));

  for (const edge of copy.edges) {
    if (was.has(edge.from) && was.has(edge.to) && !hasEdge(inService.graph.edges, edge)) {
      changes.push({
        from: byKey.get(edge.from) ?? edge.from,
        kind: 'follow',
        to: byKey.get(edge.to) ?? edge.to,
      });
    }
  }

  return changes;
}
