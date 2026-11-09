// Client-side draft shape used while building a flow in the Create Flow
// builder, before it's submitted as a CreateFlowRequest. Distinct from
// FlowNode (the read model returned by the backend) because a draft node
// carries no run state (status/output/errorMessage/runId) and instead
// caches the selected agent/provider display names so node cards can show
// a title without re-deriving it from the agents/providers lists.
export type FlowNodeDraft = {
  agentId: string;
  agentName: string;
  approvalClasses: string[];
  askPastMicros?: number;
  clientId: string;
  goal: string;
  maxSteps: number;
  providerId: string;
  providerModel: string;
  providerName: string;
  purpose: string[];
  spendCapMicros?: number;
  toolNames: string[];
};
