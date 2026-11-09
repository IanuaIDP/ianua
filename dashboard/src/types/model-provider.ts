export type ModelProviderKind = 'anthropic' | 'openai' | 'self_hosted';

export type ModelProviderStatus = 'Active' | 'Disabled';

export type ModelProviderAction = 'Delete' | 'Disable provider' | 'Enable provider';

export type ModelProvider = {
  clearance: string | null;
  embeddingModel: string | null;
  pricing: { inputMicrosPerMillion: number; outputMicrosPerMillion: number } | null;
  endpoint: string;
  hasCredential: boolean;
  id: string;
  kind: ModelProviderKind;
  lastTestMessage?: string;
  lastTestStatus?: 'failed' | 'passed';
  lastTestedAt?: Date;
  model: string;
  name: string;
  status: ModelProviderStatus;
};

export type ModelProviderTestResult = {
  ok: boolean;
  sample: string;
};

export type ModelProviderTestState =
  | { status: 'error'; message: string; testedAt: Date }
  | { status: 'pending' }
  | { status: 'success'; result: ModelProviderTestResult; testedAt: Date };
