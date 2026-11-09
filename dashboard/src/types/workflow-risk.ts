/** What a raised operation counts as: nothing weaker than these raises anything. */
export type RiskEffect = 'admin' | 'configure' | 'delete' | 'financial' | 'undeclared';

export type WorkflowRisk = {
  createdAt: string;
  effect: RiskEffect | string;
  id: string;
  integration: string;
  operation: string;
  raisedBy: string;
  updatedAt: string;
};
