export type EvaluationCheckBody = {
  at: string;
  kind: 'contains' | 'equals' | 'matches';
  pattern?: string;
  text?: string;
  value?: unknown;
};

export type EvaluationCaseBody = {
  checks: EvaluationCheckBody[];
  exposure: string;
  input: unknown;
  name: string;
};

export type EvaluationCaseView = {
  checks: EvaluationCheckBody[] | null;
  exposure: string;
  input: unknown;
  name: string;
  withheld: boolean;
};

export type EvaluationSet = {
  cases: EvaluationCaseView[];
  publishGate: string;
};

export type EvaluationDifference = {
  check: number | null;
  found: string | null;
  kind: string;
  runEnd: string | null;
};

export type EvaluationCaseResult = {
  case: EvaluationCaseView;
  differences: EvaluationDifference[] | null;
  executionId: string | null;
  outcome: string;
  reason: string | null;
  withheldExposure: string | null;
};

export type Evaluation = {
  cases: EvaluationCaseResult[];
  createdAt: string;
  id: string;
  status: string;
  version: number;
};
