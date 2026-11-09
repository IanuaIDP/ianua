import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import {
  fromSignInPolicy,
  toSignInPolicy,
  type SignInPolicyResponse,
} from '@/lib/api/services/sign-in-policy';
import type { OrgAuthConfigInput } from '@/schemas/auth-config-schemas';
import { toReenteredProofBody, type ReenteredProofBody } from '@/lib/api/reentered-proof';
import type { ReenteredProof } from '@/types/auth';
import type {
  BreachedPasswordsAction,
  CharacterRequirements,
  MfaPolicy,
  OrgAuthConfig,
  OrgAuthMethod,
  OrgSsoPolicy,
  SecondFactorKind,
} from '@/types/auth-config';

type OrgAuthConfigResponse = {
  breached_passwords?: BreachedPasswordsAction;
  challenge_threshold?: number;
  enabled_methods: OrgAuthMethod[];
  idle_timeout_secs: number;
  ip_allowlist: string[];
  lockout_duration_secs: number;
  max_login_attempts: number;
  mfa_policy: MfaPolicy;
  password_policy: { min_length: number; require: CharacterRequirements };
  second_factors?: SecondFactorKind[];
  session_lifetime_secs: number;
  sso?: OrgSsoPolicy;
  step_up: SignInPolicyResponse;
};

type UpdateOrgAuthConfigRequest = OrgAuthConfigResponse & {
  proof: ReenteredProofBody;
};

function getOrgAuthConfigEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/auth-config`;
}

function toOrgAuthConfig(response: OrgAuthConfigResponse): OrgAuthConfig {
  return {
    breachedPasswords: response.breached_passwords,
    challengeThreshold: response.challenge_threshold,
    enabledMethods: response.enabled_methods,
    idleTimeoutSecs: response.idle_timeout_secs,
    ipAllowlist: response.ip_allowlist,
    lockoutDurationSecs: response.lockout_duration_secs,
    maxLoginAttempts: response.max_login_attempts,
    mfaPolicy: response.mfa_policy,
    passwordPolicy: {
      minLength: response.password_policy.min_length,
      require: response.password_policy.require,
    },
    secondFactors: response.second_factors,
    sessionLifetimeSecs: response.session_lifetime_secs,
    sso: response.sso,
    stepUp: toSignInPolicy(response.step_up),
  };
}

export async function getOrgAuthConfig(orgSlug: string): Promise<OrgAuthConfig> {
  const response = await getList<OrgAuthConfigResponse>(getOrgAuthConfigEndpoint(orgSlug));

  return toOrgAuthConfig(response);
}

export async function updateOrgAuthConfig(
  orgSlug: string,
  payload: OrgAuthConfigInput,
  proof: ReenteredProof,
): Promise<void> {
  const body: UpdateOrgAuthConfigRequest = {
    breached_passwords: payload.breachedPasswords,
    challenge_threshold: payload.challengeThreshold,
    enabled_methods: payload.enabledMethods,
    idle_timeout_secs: payload.idleTimeoutSecs,
    ip_allowlist: payload.ipAllowlist,
    lockout_duration_secs: payload.lockoutDurationSecs,
    max_login_attempts: payload.maxLoginAttempts,
    mfa_policy: payload.mfaPolicy,
    password_policy: {
      min_length: payload.passwordPolicy.minLength,
      require: payload.passwordPolicy.require,
    },
    proof: toReenteredProofBody(proof),
    second_factors: payload.secondFactors,
    session_lifetime_secs: payload.sessionLifetimeSecs,
    sso: payload.sso,
    step_up: fromSignInPolicy(payload.stepUp),
  };

  await apiClient.put(getOrgAuthConfigEndpoint(orgSlug), body);
}
