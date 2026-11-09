export type ApprovalStatus = 'Approved' | 'AwaitingApproval' | 'Denied' | 'Expired';

export type ApprovalAction = 'Approve' | 'Deny';

export type Approval = {
  action: string;
  agentId: string;
  /** Two when the approval needs a second person, after `firstApprovedBy`. */
  approversNeeded: number;
  decidedAt?: string;
  delegationId: string;
  expiresAt: string;
  firstApprovedBy?: string;
  id: string;
  pendingArguments?: string;
  pendingTool?: string;
  purpose?: string;
  requestedBy?: string;
  runId?: string;
  status: ApprovalStatus;
};
