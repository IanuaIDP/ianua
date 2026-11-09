export type TenantAgentStatus = 'Active' | 'Suspended' | 'Revoked';

/** Whether an agent may act right now. An active agent can still owe a re-attestation. */
export type TenantAgentStanding = TenantAgentStatus | 'MustReattest';

export type TenantAgentTab = 'All' | TenantAgentStatus;

export type TenantAgentAction =
  'Edit' | 'Suspend' | 'Resume' | 'Revoke' | 'RequireReattestation' | 'Contain' | 'Delete';

export type TenantAgentSortField = 'created_at' | 'updated_at' | 'name' | 'status';

export type TenantAgentSortDirection = 'asc' | 'desc';

export type TenantAgentOwnerKind = 'user' | 'org_user' | 'agent';

export type TenantAgentOwner = {
  displayName?: string;
  id: string;
  kind: TenantAgentOwnerKind;
};

export type TenantAgent = {
  attestationMethods: string[];
  attestationOrigins: string[];
  created: string;
  description: string;
  id: string;
  name: string;
  /** When an open offer to hand this agent over runs out. */
  offerExpiresAt: string | null;
  offeredTo: TenantAgentOwner | null;
  owner: TenantAgentOwner;
  reattestIntervalSeconds: number | null;
  standing: TenantAgentStanding;
  status: TenantAgentStatus;
  updated: string;
  workloadTrusts: { issuer: string; method: string; subject: string }[];
};

export type TenantAgentOwnerDisplay = {
  initial: string;
  name: string;
  secondary: string;
  seed: string;
};
