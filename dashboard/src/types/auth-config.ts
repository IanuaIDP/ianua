export type AuthMethod = 'Password' | 'MagicLink' | 'Passkey' | 'Saml' | 'Oidc';

export type MfaPolicy = 'Disabled' | 'Optional' | 'Required';

export type AssuranceLevel = 'Aal1' | 'Aal2' | 'Aal3';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export type BreachedPasswordsAction = 'Off' | 'Warn' | 'Block';

export type SecondFactorKind = 'Totp' | 'EmailCode' | 'SmsCode';

export type ImpersonationConsent = 'AdminDecides' | 'HolderApproves';

export type OrgSsoPolicy = 'Optional' | 'Enforced';

export type CharacterRequirements = {
  digit: boolean;
  lowercase: boolean;
  special: boolean;
  uppercase: boolean;
};

export type PasswordPolicy = {
  minLength: number;
  require: CharacterRequirements;
};

export type SignInPolicy = {
  baselineAal: AssuranceLevel;
  denyRiskThreshold: RiskLevel;
  mfaRiskThreshold: RiskLevel;
  requireMfaNewCountry: boolean;
  requireMfaNewDevice: boolean;
  sensitiveAal: AssuranceLevel;
};

export type AuthConfig = {
  breachedPasswords?: BreachedPasswordsAction;
  challengeThreshold?: number;
  enabledMethods: AuthMethod[];
  impersonationConsent?: ImpersonationConsent;
  secondFactors?: SecondFactorKind[];
  idleTimeoutSecs: number;
  ipAllowlist: string[];
  jwtIssuer?: string;
  lockoutDurationSecs: number;
  maxLoginAttempts: number;
  mfaPolicy: MfaPolicy;
  passwordPolicy: PasswordPolicy;
  selfRegistration: boolean;
  sessionLifetimeSecs: number;
  stepUp: SignInPolicy;
};

// The only ways into the management plane. Org sign-in implements no others,
// and the server refuses the rest, so the narrower type is the honest one.
export type OrgAuthMethod = Extract<AuthMethod, 'Password' | 'Passkey'>;

// How the organization's own admins sign in, which is a separate question from
// how any one workspace's users do. Two fields are absent on purpose: nothing
// proxies an organization's traffic, so there is no issuer to pin, and an
// organization exists before anyone could register into it.
export type OrgAuthConfig = {
  breachedPasswords?: BreachedPasswordsAction;
  challengeThreshold?: number;
  enabledMethods: OrgAuthMethod[];
  secondFactors?: SecondFactorKind[];
  sso?: OrgSsoPolicy;
  idleTimeoutSecs: number;
  ipAllowlist: string[];
  lockoutDurationSecs: number;
  maxLoginAttempts: number;
  mfaPolicy: MfaPolicy;
  passwordPolicy: PasswordPolicy;
  sessionLifetimeSecs: number;
  stepUp: SignInPolicy;
};
