export type PipelineStatus = 'Draft' | 'Active' | 'Disabled';

export type PipelineAction = 'Activate' | 'Disable' | 'Delete';

export type StageStatus = 'Enabled' | 'Disabled';

export type StageKind =
  | 'Identity'
  | 'Policy'
  | 'Waf'
  | 'GeoFence'
  | 'RateLimit'
  | 'Cors'
  | 'SecurityHeaders'
  | 'IpReputation'
  | 'CanaryToken'
  | 'HoneypotRoutes'
  | 'ReconDetection'
  | 'Fingerprint'
  | 'DataClassify'
  | 'TokenExchange'
  | 'StepUp'
  | 'RequestSign'
  | 'Redact'
  | 'ResponseSign'
  | 'Cache'
  | 'GraphQl'
  | 'Mcp'
  | 'RequestTransform'
  | 'ResponseTransform'
  | 'Terminate'
  | 'TokenRateLimit'
  | 'Custom';

export type StageAction = 'Enable' | 'Disable' | 'Delete';

export type Stage = {
  id: string;
  isMandatory: boolean;
  kind: StageKind;
  position: number;
  status: StageStatus;
};

export type WafRuleSet = 'Sqli' | 'Xss' | 'Traversal' | 'CommandInjection' | 'PromptInjection';

export type WafStageConfig = {
  anomalyThreshold: number;
  maxBodyBytes: number;
  ruleSets: WafRuleSet[];
};

export type RateLimitKeyBy = 'UserId' | 'IpAddress' | 'ApiKey' | 'Tenant' | 'ConsumerId';

export type RateLimitStageConfig = {
  keyBy: RateLimitKeyBy;
  maxRequests: number;
  windowSeconds: number;
};

export type CanaryTokenStageConfig = {
  tokens: string[];
};

export type CustomStageConfig = {
  maxMemoryBytes: number;
  /** Content-addressed reference returned by uploading the module. */
  moduleRef: string;
  timeoutMs: number;
};

export type HeaderEntry = {
  name: string;
  /**
   * Written literally, or as a secret reference — `{env://NAME}`,
   * `{file:///path}`, `{vault://path#key}` — resolved by the proxy at request
   * time so the value is never stored here.
   */
  value: string;
};

export type RequestTransformStageConfig = {
  removeHeaders: string[];
  removeQuery: string[];
  setHeaders: HeaderEntry[];
  setQuery: HeaderEntry[];
};

export type ResponseTransformStageConfig = {
  removeHeaders: string[];
  setHeaders: HeaderEntry[];
};

export type GraphQlStageConfig = {
  /**
   * How many rate-limit units a complexity point is worth. Zero counts every
   * GraphQL request as one, whatever it asks for.
   */
  costPerComplexity: number;
  maxComplexity: number;
  maxDepth: number;
};

/**
 * Stage kinds we can currently build a valid add-stage payload for. The
 * remaining live kinds (GeoFence, Cors, SecurityHeaders, IpReputation,
 * HoneypotRoutes, ReconDetection, Fingerprint, DataClassify, TokenExchange,
 * StepUp, RequestSign, Redact, ResponseSign, Cache) will be specified once we
 * have their config shapes. Extend this union once those shapes are confirmed.
 */
/// Whose response shape the token counts are read from. The two providers put
/// them in different places, so reading one as the other counts nothing.
export type LlmDialect = 'open_ai' | 'anthropic';

/**
 * What to charge when the answer never said what it cost.
 *
 * A caller decides whether usage is reported — it can stream, or simply not
 * ask — so charging nothing would make the limit advisory. `charge` is the
 * default for that reason; `ignore` is a deliberate hole.
 */
export type UnknownUsage = { charge: number } | 'ignore';

export type TokenRateLimitStageConfig = {
  dialect: LlmDialect;
  keyBy: RateLimitKeyBy;
  maxTokens: number;
  onUnknown: UnknownUsage;
  windowSeconds: number;
};

export type AddableStagePayload =
  | { config: WafStageConfig; kind: 'Waf' }
  | { config: RateLimitStageConfig; kind: 'RateLimit' }
  | { config: CanaryTokenStageConfig; kind: 'CanaryToken' }
  | { config: GraphQlStageConfig; kind: 'GraphQl' }
  | { config: RequestTransformStageConfig; kind: 'RequestTransform' }
  | { config: ResponseTransformStageConfig; kind: 'ResponseTransform' }
  | { config: TokenRateLimitStageConfig; kind: 'TokenRateLimit' }
  | { config: CustomStageConfig; kind: 'Custom' };

export type Pipeline = {
  created: string;
  id: string;
  name: string;
  stages: Stage[];
  status: PipelineStatus;
  updated: string;
};

/**
 * One pipeline in the tenant's listing.
 *
 * `routeCount` is what says whether it can be deleted: a pipeline still named
 * by a route is refused, and knowing that before asking is the difference
 * between a disabled action and an error.
 */
export type PipelineSummary = {
  created: string;
  id: string;
  name: string;
  routeCount: number;
  stageCount: number;
  status: PipelineStatus;
  updated: string;
};
