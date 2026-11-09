// Landing page structure: ids, links, icons and layout hints. The text for each
// id is in messages/<language>.json under `landing`.

export const LANDING_NAV_ITEMS = [
  { id: 'problem', href: '#problem' },
  { id: 'howItWorks', href: '#how-it-works' },
  { id: 'whatYouGet', href: '#what-you-get' },
  { id: 'aiAgents', href: '#ai-agents' },
  { id: 'whyIanua', href: '#why-Ianua' },
  { id: 'security', href: '#security' },
  { id: 'useCases', href: '#use-cases' },
  { id: 'pricing', href: '#pricing' },
  { id: 'faq', href: '#faq' },
  { id: 'contact', href: '#contact' },
] as const;

export const LANDING_LEGAL_LINKS = [
  { id: 'helpCenter', href: '/help-center' },
  { id: 'privacyPolicy', href: '/privacy-policy' },
  { id: 'termsOfUse', href: '/terms-of-use' },
  { id: 'contactSupport', href: 'mailto:support@ianua.io' },
] as const;

export const LEGAL_NAV_ITEMS = [
  { id: 'privacyPolicy', href: '/privacy-policy' },
  { id: 'termsOfUse', href: '/terms-of-use' },
] as const;

export const HERO_TRUST_POINT_IDS = ['openStandards', 'noPerUserPricing', 'dataInCountry'] as const;

export const HERO_TECHNOLOGY_IDS = [
  'oidc',
  'saml',
  'oauth',
  'scim',
  'mtls',
  'passkeys',
  'aiAgentIdentity',
  'tamperEvidentAudit',
  'builtInRust',
] as const;

export const HOW_IT_WORKS_STEPS = [
  { id: 'stop', number: '01' },
  { id: 'identify', number: '02' },
  { id: 'understand', number: '03' },
  { id: 'decide', number: '04' },
  { id: 'act', number: '05' },
  { id: 'handOff', number: '06' },
  { id: 'record', number: '07' },
] as const;

export const PER_REQUEST_CHECK_GROUPS = [
  { id: 'identityPolicy', icon: 'policy' },
  { id: 'riskContext', icon: 'gpp_maybe' },
  { id: 'threatProtection', icon: 'security' },
  { id: 'boundTokens', icon: 'token' },
  { id: 'dataProtection', icon: 'database' },
  { id: 'customLogic', icon: 'flowchart' },
] as const;

type AiAgentFeature = {
  icon: string;
  id: 'approval' | 'blastRadius' | 'borrow' | 'prove' | 'stop' | 'talk';
  size: 'normal' | 'wide';
  tall?: boolean;
};

export const AI_AGENTS_FEATURES: AiAgentFeature[] = [
  { id: 'borrow', icon: 'key', size: 'wide' },
  { id: 'prove', icon: 'verified_user', size: 'normal', tall: true },
  { id: 'approval', icon: 'approval_delegation', size: 'normal' },
  { id: 'blastRadius', icon: 'radar', size: 'normal' },
  { id: 'talk', icon: 'hub', size: 'wide', tall: true },
  { id: 'stop', icon: 'block', size: 'normal', tall: true },
];

export const WHY_IANUA_REASONS = [
  { id: 'neverFailsOpen', number: '1' },
  { id: 'loginAndGateway', number: '2' },
  { id: 'yourAccount', number: '3' },
  { id: 'tryRule', number: '4' },
  { id: 'runIt', number: '5' },
] as const;

export const SECURITY_CARDS = [
  { id: 'auditLog', icon: 'fact_check' },
  { id: 'tokens', icon: 'vpn_key' },
  { id: 'noBlindTrust', icon: 'visibility' },
  { id: 'secrets', icon: 'lock' },
  { id: 'jurisdiction', icon: 'account_tree' },
  { id: 'domain', icon: 'language' },
] as const;

export const USE_CASES = [
  { id: 'internalApps' },
  { id: 'customerLogin' },
  { id: 'replaceStack' },
] as const;

export const FAQ_ITEM_IDS = [
  'whoRuns',
  'dataLocation',
  'whatIfBreaks',
  'moveFromOkta',
  'versusCloudflare',
  'aiAgents',
  'auditProof',
  'standards',
  'perUser',
  'separation',
  'changeApps',
] as const;
