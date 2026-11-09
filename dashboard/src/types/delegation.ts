export type DelegationOwnerKind = 'agent' | 'consumer' | 'org_user' | 'user';

export type DelegationOwner = {
  displayName: string | null;
  id: string;
  kind: DelegationOwnerKind;
};

export type DelegationDriftMode = 'enforce' | 'off' | 'warn';

export type DelegationIntent = {
  mode: DelegationDriftMode;
  statement: string;
  thresholdBasisPoints: number | null;
};

export type DelegationBudget = {
  maxRequests: number;
  usedRequests: number | null;
  windowSeconds: number;
};

export type DelegationPubSubRights = 'both' | 'publish' | 'subscribe';

export type DelegationTopicCapability = {
  rights: DelegationPubSubRights;
  topic: string;
};

export type DelegationResourceCapability = {
  relation: string;
  resource: string;
};

export type DelegationCapabilities = {
  mcpPrompts: string[];
  mcpResources: string[];
  http: string[];
  messaging: DelegationTopicCapability[];
  resources: DelegationResourceCapability[];
  tools: string[];
};

export type DelegationStatus = 'Active' | 'Expired' | 'Revoked';

export type DelegationAction = 'Revoke';

export type Delegation = {
  /// The services (by id) the agent may call through the gateway; `null`
  /// when it reaches none that require sign-in.
  apps: string[] | null;
  budget: DelegationBudget | null;
  delegate: string;
  delegationId: string;
  delegator: DelegationOwner;
  depth: number;
  expiresAt: string;
  granted: DelegationCapabilities;
  intent: DelegationIntent | null;
  maxDepth: number;
  name: string | null;
  parent: string | null;
  requiresApproval: boolean;
  resourceScope: string[] | null;
  revoked: boolean;
  senderConstrained: boolean;
  status: DelegationStatus;
  task: string | null;
};
