import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import {
  fromSignInPolicy,
  toSignInPolicy,
  type SignInPolicyResponse,
} from '@/lib/api/services/sign-in-policy';
import type { AuthConfigInput } from '@/schemas/auth-config-schemas';
import { toFreshProofBody, type FreshProofBody } from '@/lib/api/reentered-proof';
import type { ReenteredProof } from '@/types/auth';
import type {
  AuthConfig,
  AuthMethod,
  BreachedPasswordsAction,
  CharacterRequirements,
  ImpersonationConsent,
  MfaPolicy,
  SecondFactorKind,
} from '@/types/auth-config';

type AuthConfigResponse = {
  breached_passwords?: BreachedPasswordsAction;
  challenge_threshold?: number;
  enabled_methods: AuthMethod[];
  idle_timeout_secs: number;
  impersonation_consent?: ImpersonationConsent;
  ip_allowlist: string[];
  jwt_issuer?: string | null;
  lockout_duration_secs: number;
  max_login_attempts: number;
  mfa_policy: MfaPolicy;
  password_policy: { min_length: number; require: CharacterRequirements };
  second_factors?: SecondFactorKind[];
  self_registration: boolean;
  session_lifetime_secs: number;
  step_up: SignInPolicyResponse;
};

type UpdateAuthConfigRequest = AuthConfigResponse & {
  proof: FreshProofBody;
};

function getAuthConfigEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/auth-config`;
}

function toAuthConfig(response: AuthConfigResponse): AuthConfig {
  return {
    breachedPasswords: response.breached_passwords,
    challengeThreshold: response.challenge_threshold,
    enabledMethods: response.enabled_methods,
    idleTimeoutSecs: response.idle_timeout_secs,
    impersonationConsent: response.impersonation_consent,
    ipAllowlist: response.ip_allowlist,
    jwtIssuer: response.jwt_issuer ?? undefined,
    lockoutDurationSecs: response.lockout_duration_secs,
    maxLoginAttempts: response.max_login_attempts,
    mfaPolicy: response.mfa_policy,
    passwordPolicy: {
      minLength: response.password_policy.min_length,
      require: response.password_policy.require,
    },
    secondFactors: response.second_factors,
    selfRegistration: response.self_registration,
    sessionLifetimeSecs: response.session_lifetime_secs,
    stepUp: toSignInPolicy(response.step_up),
  };
}

export async function getAuthConfig(orgSlug: string, tenantSlug: string): Promise<AuthConfig> {
  const response = await getList<AuthConfigResponse>(getAuthConfigEndpoint(orgSlug, tenantSlug));

  return toAuthConfig(response);
}

export async function updateAuthConfig(
  orgSlug: string,
  tenantSlug: string,
  payload: AuthConfigInput,
  proof: ReenteredProof,
): Promise<void> {
  const body: UpdateAuthConfigRequest = {
    breached_passwords: payload.breachedPasswords,
    challenge_threshold: payload.challengeThreshold,
    enabled_methods: payload.enabledMethods,
    idle_timeout_secs: payload.idleTimeoutSecs,
    impersonation_consent: payload.impersonationConsent,
    ip_allowlist: payload.ipAllowlist,
    jwt_issuer: payload.jwtIssuer,
    lockout_duration_secs: payload.lockoutDurationSecs,
    max_login_attempts: payload.maxLoginAttempts,
    mfa_policy: payload.mfaPolicy,
    password_policy: {
      min_length: payload.passwordPolicy.minLength,
      require: payload.passwordPolicy.require,
    },
    proof: toFreshProofBody(proof),
    second_factors: payload.secondFactors,
    self_registration: payload.selfRegistration,
    session_lifetime_secs: payload.sessionLifetimeSecs,
    step_up: fromSignInPolicy(payload.stepUp),
  };

  await apiClient.put(getAuthConfigEndpoint(orgSlug, tenantSlug), body);
}
