import type { DataClassLevel } from '@/types/classification';

export type FlowStatus = 'Running' | 'Completed' | 'Failed' | 'Canceled';

export type FlowNodeStatus = 'Pending' | 'Dispatched' | 'Completed' | 'Failed';

export type FlowNode = {
  agentId: string;
  approvalClasses: string[];
  errorMessage: string | null;
  goal: string;
  maxSteps: number;
  output: string | null;
  outputExposure: DataClassLevel;
  providerId: string;
  purpose: string[];
  runId: string | null;
  status: FlowNodeStatus;
  toolNames: string[];
};

export type Flow = {
  createdAt: string;
  currentStage: number;
  description: string | null;
  id: string;
  name: string;
  stages: FlowNode[][];
  status: FlowStatus;
};

export type FlowAction = 'Cancel' | 'Delete';

export type FlowList = {
  items: Flow[];
  limit: number;
  nextCursor: string | null;
};
