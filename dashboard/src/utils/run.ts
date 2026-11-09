import type { RunSummary } from '@/types/run';

export function getRunDisplayId(run: Pick<RunSummary, 'id'>) {
  return `run-${run.id.slice(-4)}`;
}
