import type { AssuranceLevel, RiskLevel, SignInPolicy } from '@/types/auth-config';

/**
 * The step-up policy as the server states it.
 *
 * Identical on a workspace and an organization, so both services map it
 * through here rather than each keeping its own copy of the same six fields.
 */
export type SignInPolicyResponse = {
  baseline_aal: AssuranceLevel;
  deny_risk_threshold: RiskLevel;
  mfa_risk_threshold: RiskLevel;
  require_mfa_new_country: boolean;
  require_mfa_new_device: boolean;
  sensitive_aal: AssuranceLevel;
};

export function toSignInPolicy(response: SignInPolicyResponse): SignInPolicy {
  return {
    baselineAal: response.baseline_aal,
    denyRiskThreshold: response.deny_risk_threshold,
    mfaRiskThreshold: response.mfa_risk_threshold,
    requireMfaNewCountry: response.require_mfa_new_country,
    requireMfaNewDevice: response.require_mfa_new_device,
    sensitiveAal: response.sensitive_aal,
  };
}

export function fromSignInPolicy(policy: SignInPolicy): SignInPolicyResponse {
  return {
    baseline_aal: policy.baselineAal,
    deny_risk_threshold: policy.denyRiskThreshold,
    mfa_risk_threshold: policy.mfaRiskThreshold,
    require_mfa_new_country: policy.requireMfaNewCountry,
    require_mfa_new_device: policy.requireMfaNewDevice,
    sensitive_aal: policy.sensitiveAal,
  };
}
