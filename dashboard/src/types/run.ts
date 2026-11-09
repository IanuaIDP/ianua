import type { DataClassLevel } from '@/types/classification';

export type RunStatus =
  | 'AwaitingApproval'
  | 'Canceled'
  | 'Completed'
  | 'Failed'
  | 'Halted'
  | 'OverBudget'
  | 'Paused'
  | 'Running';

export type RunStepOutcome = 'allowed' | 'answered' | 'denied';

export type RunStep = {
  arguments: string | null;
  detail: string;
  outcome: RunStepOutcome;
  seq: number;
  tool: string | null;
};

export type RunSummary = {
  agentId: string;
  answer: string | null;
  approvalClasses?: string[];
  created: string;
  exposure: DataClassLevel;
  goal: string;
  id: string;
  maxSteps?: number;
  pendingArguments: string | null;
  pendingTool: string | null;
  providerId: string;
  purpose: string[];
  spendLimitMicros: number | null;
  spentMicros: number;
  startedBy: string | null;
  status: RunStatus;
  usage: { inputTokens: number; outputTokens: number };
};

export type Run = RunSummary & {
  steps: RunStep[];
};

export type RunPage = {
  items: RunSummary[];
  nextCursor: string | null;
  limit: number;
};

export type RunAction = 'Stop run' | 'View trace';
