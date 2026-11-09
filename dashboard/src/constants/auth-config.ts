import type { AuthConfig, AuthMethod, OrgAuthConfig, OrgAuthMethod } from '@/types/auth-config';

// Every way a tenant can let people sign in, in the order they appear.
export const AUTH_METHOD_ORDER: AuthMethod[] = ['Password', 'Passkey', 'MagicLink', 'Saml', 'Oidc'];

export const MFA_POLICY_IDS = ['Disabled', 'Optional', 'Required'] as const;
export const ASSURANCE_LEVEL_IDS = ['Aal1', 'Aal2', 'Aal3'] as const;
export const RISK_LEVEL_IDS = ['Low', 'Medium', 'High', 'Critical'] as const;

// The only ways into the management plane. Federation and the social
// providers are absent because org sign-in implements none of them.
export const ORG_AUTH_METHOD_ORDER: OrgAuthMethod[] = ['Password', 'Passkey'];

export const DEFAULT_ORG_AUTH_CONFIG: OrgAuthConfig = {
  enabledMethods: ['Password', 'Passkey'],
  idleTimeoutSecs: 3600,
  ipAllowlist: [],
  lockoutDurationSecs: 900,
  maxLoginAttempts: 10,
  mfaPolicy: 'Required',
  passwordPolicy: {
    minLength: 12,
    require: { digit: true, lowercase: true, special: false, uppercase: true },
  },
  sessionLifetimeSecs: 28800,
  stepUp: {
    baselineAal: 'Aal1',
    denyRiskThreshold: 'Critical',
    mfaRiskThreshold: 'Critical',
    requireMfaNewCountry: false,
    requireMfaNewDevice: false,
    sensitiveAal: 'Aal2',
  },
};

export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  enabledMethods: ['Password', 'Passkey'],
  idleTimeoutSecs: 3600,
  ipAllowlist: [],
  lockoutDurationSecs: 900,
  maxLoginAttempts: 10,
  mfaPolicy: 'Disabled',
  passwordPolicy: {
    minLength: 12,
    require: { digit: true, lowercase: true, special: false, uppercase: true },
  },
  selfRegistration: false,
  sessionLifetimeSecs: 28800,
  stepUp: {
    baselineAal: 'Aal1',
    denyRiskThreshold: 'Critical',
    mfaRiskThreshold: 'Critical',
    requireMfaNewCountry: false,
    requireMfaNewDevice: false,
    sensitiveAal: 'Aal2',
  },
};
