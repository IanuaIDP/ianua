import type { LlmDialect, RateLimitKeyBy, StageKind, WafRuleSet } from '@/types/pipeline';

export const MANDATORY_STAGE_KINDS: StageKind[] = ['Identity', 'Policy'];

export const LIVE_STAGE_KINDS: StageKind[] = [
  'Waf',
  'GeoFence',
  'RateLimit',
  'Cors',
  'SecurityHeaders',
  'IpReputation',
  'CanaryToken',
  'HoneypotRoutes',
  'ReconDetection',
  'Fingerprint',
  'DataClassify',
  'TokenExchange',
  'StepUp',
  'RequestSign',
  'Redact',
  'ResponseSign',
  'Cache',
  'GraphQl',
  'Mcp',
  'RequestTransform',
  'ResponseTransform',
  'Terminate',
  'Custom',
];

/// Every stage kind; the visible names are `dashboard.pipelines.stageKinds.<kind>` and
/// `dashboard.pipelines.stageDescriptions.<kind>`.
export const STAGE_KINDS: StageKind[] = [
  'Identity',
  'Policy',
  'Waf',
  'GeoFence',
  'RateLimit',
  'Cors',
  'SecurityHeaders',
  'IpReputation',
  'CanaryToken',
  'HoneypotRoutes',
  'ReconDetection',
  'Fingerprint',
  'DataClassify',
  'TokenExchange',
  'StepUp',
  'RequestSign',
  'Redact',
  'ResponseSign',
  'Cache',
  'GraphQl',
  'Mcp',
  'RequestTransform',
  'ResponseTransform',
  'Terminate',
  'TokenRateLimit',
  'Custom',
];

export const MAX_GRAPHQL_DEPTH = 64;
export const MAX_GRAPHQL_COMPLEXITY = 1_000_000;
export const MAX_GRAPHQL_COST_PER_COMPLEXITY = 1_000;

export const CONFIGURABLE_STAGE_KINDS: StageKind[] = [
  'Waf',
  'RateLimit',
  'TokenRateLimit',
  'CanaryToken',
  'GraphQl',
  'RequestTransform',
  'ResponseTransform',
  'Custom',
];

export const MAX_TOKEN_BUDGET = 100_000_000;
export const MIN_TOKEN_WINDOW_SECONDS = 1;
export const MAX_TOKEN_WINDOW_SECONDS = 86_400;

export const LLM_DIALECTS: LlmDialect[] = ['open_ai', 'anthropic'];

export const WAF_RULE_SETS: WafRuleSet[] = [
  'Sqli',
  'Xss',
  'Traversal',
  'CommandInjection',
  'PromptInjection',
];

export const ALL_WAF_RULE_SETS: WafRuleSet[] = WAF_RULE_SETS;

export const RATE_LIMIT_KEY_BY_IDS: RateLimitKeyBy[] = [
  'IpAddress',
  'UserId',
  'ApiKey',
  'Tenant',
  'ConsumerId',
];

export function isKeyByValue(value: string): value is RateLimitKeyBy {
  return (RATE_LIMIT_KEY_BY_IDS as string[]).includes(value);
}

export function isMandatoryStageKind(kind: StageKind) {
  return (MANDATORY_STAGE_KINDS as StageKind[]).includes(kind);
}

export function isLiveStageKind(kind: StageKind) {
  return (
    (LIVE_STAGE_KINDS as StageKind[]).includes(kind) ||
    (MANDATORY_STAGE_KINDS as StageKind[]).includes(kind)
  );
}
