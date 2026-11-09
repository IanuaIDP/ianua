import { createResource } from '@/lib/api/crud';
import { apiClient } from '@/lib/api/client';
import { toReenteredProofBody } from '@/lib/api/reentered-proof';
import type {
  Access,
  LoginRequest,
  LoginResponse,
  OrgRole,
  PasswordBreach,
  ReenteredProof,
} from '@/types/auth';
import type { CharacterRequirements, PasswordPolicy } from '@/types/auth-config';

type OrgAccessTenantResponse = {
  display_name: string;
  permissions: string[];
  roles: string[];
  slug: string;
  tenant_id: string;
};

export type OrgAccessResponse = {
  role: OrgRole;
  tenants: OrgAccessTenantResponse[];
};

export type OrgLoginAuthenticatedResponse = {
  access?: OrgAccessResponse | null;
  email_confirmation_required: boolean;
  mfa_enrollment_required: boolean;
  mfa_required: boolean;
  org_slug: string;
  organization_id: string;
  organization_name: string;
  refresh_token: string;
  session_id: string;
  status: 'authenticated';
  tenant_id?: string | null;
  tenant_slug?: string | null;
  display_name: string;
};

type OfferedOrganizationResponse = {
  name: string;
  organization_id: string;
  slug: string;
};

type OrgLoginChooseOrganizationResponse = {
  organizations: OfferedOrganizationResponse[];
  status: 'choose_organization';
};

export type OrgLoginResponse = OrgLoginAuthenticatedResponse | OrgLoginChooseOrganizationResponse;

export type TenantAuthContext = {
  orgSlug: string;
  tenantSlug: string;
};

export type OfferedOrganization = {
  name: string;
  slug: string;
};

/** What the change a sign-in owes asks for besides the new password. */
export type DuePasswordChangeProof = 'none' | 'own_factor' | 'mailed_link';

export type LoginResult =
  | { kind: 'authenticated'; response: LoginResponse }
  | {
      kind: 'mfa_required' | 'mfa_enrollment_required';
      orgSlug: string;
      pendingResponse: LoginResponse;
      sessionId: string;
    }
  | {
      kind: 'tenant_mfa_required' | 'tenant_mfa_enrollment_required';
      orgSlug: string;
      pendingResponse: LoginResponse;
      sessionId: string;
      tenantSlug: string;
    }
  | ({ kind: 'email_confirmation_required' } & WaitingSignIn)
  | { kind: 'choose_organization'; organizations: OfferedOrganization[] }
  | {
      changeToken: string | null;
      kind: 'password_change_required';
      proof: DuePasswordChangeProof;
    };

/** A sign-in waiting for its owner to follow the link mailed to them. */
export type WaitingSignIn = {
  orgSlug: string;
  pendingResponse: LoginResponse;
  tenantSlug?: string;
};

type VerifyOrganizationMfaRequest = {
  code: string;
};

export type TenantMfaEnrollResponse = {
  otpauth_uri: string;
};

export type TenantMfaStatusResponse = {
  enabled: boolean;
  method?: string | null;
};

type TenantMfaConfirmRequest = {
  code: string;
  session_id?: string;
};

type TenantMfaConfirmResponse = {
  recovery_codes: string[];
};

type VerifyTenantMfaRequest = {
  code: string;
  session_id: string;
};

type RequestTenantPasswordResetRequest = {
  email: string;
};

type ConfirmPasswordResetRequest = {
  mfa_code?: string;
  new_password: string;
  token: string;
};

type RequestOrganizationPasswordResetRequest = {
  email: string;
};

type ConfirmOrganizationPasswordResetRequest = {
  mfa_code?: string;
  password: string;
  token: string;
};

export type VerificationTokenStatus = 'Valid' | 'Expired' | 'Verified';

type VerificationTokenStatusRequest = {
  token: string;
};

type VerificationTokenStatusResponse = {
  status: VerificationTokenStatus;
};

export type TokenStatus = 'Valid' | 'Expired' | 'AlreadyUsed' | 'Invalid';

type TokenStatusRequest = {
  token: string;
};

type TokenStatusResponse = {
  password_policy?: { min_length: number; require: CharacterRequirements };
  status: TokenStatus;
};

export type PasswordResetTokenStatus = {
  passwordPolicy: PasswordPolicy | null;
  status: TokenStatus;
};

type ResendVerificationEmailRequest = {
  token: string;
};

type ResendVerificationEmailResponse = {
  retry_after_seconds: number;
};

type ResendTokenRequest = {
  token: string;
};

type ResendTokenResponse = {
  retry_after_seconds: number;
};

type SignInOptionsResponse = {
  connections: { id: string; name: string; protocol: 'Oidc' | 'Saml' }[];
  magic_link: boolean;
  passkey: boolean;
};

export type SignInConnection = {
  href: string;
  id: string;
  name: string;
};

export type SignInOptions = {
  connections: SignInConnection[];
  magicLink: boolean;
  passkey: boolean;
};

type MagicLinkRequest = {
  email: string;
};

type ConsumeMagicLinkRequest = {
  token: string;
};

/**
 * A tenant session from a sign-in that may still wait on a second factor, or
 * on one being set up: what an emailed link and a single sign-on both return.
 */
type TenantSessionResponse = {
  mfa_enrollment_required: boolean;
  mfa_required: boolean;
  refresh_token: string;
  session_id: string;
};

type SsoExchangeRequest = {
  code: string;
  state: string;
};

export type PasswordBreachResponse = {
  occurrences?: number | null;
  status: string;
};

type PasswordSetResponse = {
  password_breach: PasswordBreachResponse;
};

type DuePasswordChangeRequest = {
  change_token: string;
  code?: string;
  fingerprint_hash?: string;
  new_password: string;
};

function getLoginEndpoint(context?: TenantAuthContext) {
  if (!context) {
    return '/login';
  }

  return `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
    context.tenantSlug,
  )}/login`;
}

function getTenantAuthEndpoint(context: TenantAuthContext, actionPath: string) {
  return `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
    context.tenantSlug,
  )}/auth/${actionPath}`;
}

export function toOrgAccess(response?: OrgAccessResponse | null): Access | null {
  if (!response) {
    return null;
  }

  return {
    role: response.role,
    tenants: response.tenants.map((tenant) => ({
      displayName: tenant.display_name,
      permissions: tenant.permissions,
      roles: tenant.roles,
      slug: tenant.slug,
      tenantId: tenant.tenant_id,
    })),
  };
}

export function toLoginResponse(
  email: string,
  response: OrgLoginAuthenticatedResponse,
): LoginResponse {
  return {
    access: toOrgAccess(response.access),
    accessToken: response.refresh_token,
    user: {
      email,
      id: response.session_id,
      name: response.display_name,
      organizationId: response.organization_id,
      organizationName: response.organization_name,
      organizationSlug: response.org_slug,
      tenantId: response.tenant_id ?? undefined,
      tenantName: response.access?.tenants.find((tenant) => tenant.slug === response.tenant_slug)
        ?.display_name,
      tenantSlug: response.tenant_slug ?? undefined,
    },
  };
}

export type TenantLoginAuthenticatedResponse = {
  display_name: string;
  email_confirmation_required: boolean;
  mfa_enrollment_required: boolean;
  mfa_required: boolean;
  refresh_token: string;
  session_id: string;
  tenant_id: string;
  tenant_name?: string | null;
};

function toTenantPasswordLoginResponse(
  context: TenantAuthContext,
  email: string,
  response: TenantLoginAuthenticatedResponse,
): LoginResponse {
  return {
    access: null,
    accessToken: response.refresh_token,
    user: {
      email,
      id: response.session_id,
      name: response.display_name,
      organizationSlug: context.orgSlug,
      tenantId: response.tenant_id,
      tenantName: response.tenant_name ?? undefined,
      tenantSlug: context.tenantSlug,
    },
  };
}

type TenantLoginPasswordChangeResponse = {
  change_token?: string | null;
  password_change_required: boolean;
  proof: DuePasswordChangeProof;
};

type TenantLoginAnswer = TenantLoginAuthenticatedResponse | TenantLoginPasswordChangeResponse;

/** Where a tenant sign-in stands: signed in, or owing a second factor or a mailed confirmation. */
export function toTenantLoginResult(
  context: TenantAuthContext,
  email: string,
  response: TenantLoginAuthenticatedResponse,
): LoginResult {
  const pendingResponse = toTenantPasswordLoginResponse(context, email, response);

  if (response.email_confirmation_required) {
    return {
      kind: 'email_confirmation_required',
      orgSlug: context.orgSlug,
      pendingResponse,
      tenantSlug: context.tenantSlug,
    };
  }

  if (response.mfa_required) {
    return {
      kind: response.mfa_enrollment_required
        ? 'tenant_mfa_enrollment_required'
        : 'tenant_mfa_required',
      orgSlug: context.orgSlug,
      pendingResponse,
      sessionId: response.session_id,
      tenantSlug: context.tenantSlug,
    };
  }

  return { kind: 'authenticated', response: pendingResponse };
}

function tenantAnswerResult(
  context: TenantAuthContext,
  email: string,
  answer: TenantLoginAnswer,
): LoginResult {
  if ('password_change_required' in answer) {
    return {
      changeToken: answer.change_token ?? null,
      kind: 'password_change_required',
      proof: answer.proof,
    };
  }

  return toTenantLoginResult(context, email, answer);
}

/** Where an organization sign-in stands, whichever way it was started. */
export function toOrgLoginResult(email: string, response: OrgLoginResponse): LoginResult {
  if (response.status === 'choose_organization') {
    return {
      kind: 'choose_organization',
      organizations: response.organizations.map(({ name, slug }) => ({ name, slug })),
    };
  }

  const pendingResponse = toLoginResponse(email, response);

  if (response.email_confirmation_required) {
    return {
      kind: 'email_confirmation_required',
      orgSlug: response.org_slug,
      pendingResponse,
    };
  }

  if (response.mfa_required) {
    return {
      kind: response.mfa_enrollment_required ? 'mfa_enrollment_required' : 'mfa_required',
      orgSlug: response.org_slug,
      pendingResponse,
      sessionId: response.session_id,
    };
  }

  return { kind: 'authenticated', response: pendingResponse };
}

export async function login(
  payload: LoginRequest,
  context?: TenantAuthContext,
): Promise<LoginResult> {
  if (context) {
    const answer = await createResource<TenantLoginAnswer, LoginRequest>(
      getLoginEndpoint(context),
      payload,
    );

    return tenantAnswerResult(context, payload.email, answer);
  }

  const response = await createResource<OrgLoginResponse, LoginRequest>(
    getLoginEndpoint(context),
    payload,
  );

  return toOrgLoginResult(payload.email, response);
}

/** Sets the new password a tenant sign-in owes, which then carries on. */
export async function completeDuePasswordChange(
  context: TenantAuthContext,
  email: string,
  change: {
    changeToken: string;
    code?: string;
    fingerprintHash?: string;
    newPassword: string;
  },
): Promise<LoginResult> {
  const answer = await createResource<TenantLoginAnswer, DuePasswordChangeRequest>(
    `${getLoginEndpoint(context)}/password-change`,
    {
      change_token: change.changeToken,
      code: change.code,
      fingerprint_hash: change.fingerprintHash,
      new_password: change.newPassword,
    },
  );

  return tenantAnswerResult(context, email, answer);
}

export function toPasswordBreach(response: PasswordBreachResponse): PasswordBreach {
  return {
    isBreached: response.status === 'breached',
    occurrences: response.occurrences ?? null,
  };
}

export function hasOrgPermission(permissions: string[], permission: string): boolean {
  if (permissions.includes(permission)) {
    return true;
  }

  const [scope, resource] = permission.split(':');

  if (!scope || !resource) {
    return false;
  }

  return permissions.includes(`${scope}:${resource}:manage`);
}

export async function getOrgAccess(orgSlug: string): Promise<Access | null> {
  const response = await apiClient.get<OrgAccessResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/me/access`,
  );

  return toOrgAccess(response.data);
}

export async function verifyOrganizationMfa(orgSlug: string, code: string): Promise<void> {
  await apiClient.post<unknown>(`/organizations/${encodeURIComponent(orgSlug)}/mfa/verify`, {
    code,
  } satisfies VerifyOrganizationMfaRequest);
}

/**
 * Starts setting up a second factor. A signed-in person proves it is them
 * with `proof`; a sign-in waiting on the set-up has its session say so instead.
 */
export async function beginTenantMfa(
  context: TenantAuthContext,
  proof?: ReenteredProof,
): Promise<TenantMfaEnrollResponse> {
  const response = await apiClient.post<TenantMfaEnrollResponse>(
    getTenantAuthEndpoint(context, 'mfa/enroll'),
    proof ? { proof: toReenteredProofBody(proof) } : undefined,
  );

  return response.data;
}

export async function getTenantMfaStatus(
  context: TenantAuthContext,
): Promise<TenantMfaStatusResponse> {
  const response = await apiClient.get<TenantMfaStatusResponse>(
    getTenantAuthEndpoint(context, 'mfa/status'),
  );

  return response.data;
}

/**
 * Confirms a new second factor and returns its recovery codes, shown once.
 * `completingSessionId` names a sign-in that was waiting on the set-up; it
 * is finished by it.
 */
export async function confirmTenantMfaEnrollment(
  context: TenantAuthContext,
  code: string,
  completingSessionId?: string,
): Promise<string[]> {
  const response = await apiClient.post<TenantMfaConfirmResponse>(
    getTenantAuthEndpoint(context, 'mfa/enroll/confirm'),
    { code, session_id: completingSessionId } satisfies TenantMfaConfirmRequest,
  );

  return response.data.recovery_codes;
}

export async function disableTenantMfa(context: TenantAuthContext, code: string): Promise<void> {
  await apiClient.delete<unknown>(getTenantAuthEndpoint(context, 'mfa'), {
    data: { code } satisfies TenantMfaConfirmRequest,
  });
}

export async function verifyTenantMfa(
  context: TenantAuthContext,
  code: string,
  sessionId: string,
): Promise<void> {
  await apiClient.post<unknown>(getTenantAuthEndpoint(context, 'mfa/verify'), {
    code,
    session_id: sessionId,
  } satisfies VerifyTenantMfaRequest);
}

type SignUpRulesResponse = {
  open: boolean;
  password_policy?: { min_length: number; require: CharacterRequirements };
};

export type SignUpRules = {
  open: boolean;
  passwordPolicy: PasswordPolicy | null;
};

type SignUpRequest = {
  display_name: string;
  email: string;
  password: string;
};

export type TenantSignUp = {
  displayName: string;
  email: string;
  password: string;
};

export async function getTenantSignUpRules(context: TenantAuthContext): Promise<SignUpRules> {
  const response = await apiClient.get<SignUpRulesResponse>(
    getTenantAuthEndpoint(context, 'sign-up'),
  );
  const policy = response.data.password_policy;

  return {
    open: response.data.open,
    passwordPolicy: policy ? { minLength: policy.min_length, require: policy.require } : null,
  };
}

/**
 * What a tenant's sign-in page offers besides a password. Each identity
 * provider's button leaves through the dashboard's own address, so the
 * sign-on's cookie and its way back stay on this site.
 */
export async function getTenantSignInOptions(context: TenantAuthContext): Promise<SignInOptions> {
  const response = await apiClient.get<SignInOptionsResponse>(
    getTenantAuthEndpoint(context, 'sign-in-options'),
  );
  const tenantBase = `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
    context.tenantSlug,
  )}`;

  return {
    connections: response.data.connections.map((connection) => ({
      href: `/api/v1${tenantBase}/federation/connections/${encodeURIComponent(connection.id)}/login`,
      id: connection.id,
      name: connection.name,
    })),
    magicLink: response.data.magic_link,
    passkey: response.data.passkey,
  };
}

/** Emails `email` a link that signs them in, if they have an account. */
export async function requestTenantMagicLink(
  context: TenantAuthContext,
  email: string,
): Promise<void> {
  await apiClient.post<unknown>(getTenantAuthEndpoint(context, 'magic-link'), {
    email,
  } satisfies MagicLinkRequest);
}

/**
 * Uses the token from an emailed sign-in link. Like a password sign-in, the
 * session may still wait on a second factor, or on one being set up.
 */
export async function consumeTenantMagicLink(
  context: TenantAuthContext,
  token: string,
): Promise<LoginResult> {
  const response = await apiClient.post<TenantSessionResponse>(
    getTenantAuthEndpoint(context, 'magic-link/verify'),
    { token } satisfies ConsumeMagicLinkRequest,
  );

  return tenantSessionResult(context, response.data);
}

type OrgConfirmedSignInResponse = {
  mfa_enrollment_required: boolean;
  session_id: string;
};

type TenantConfirmedSignInResponse = OrgConfirmedSignInResponse & {
  mfa_required: boolean;
};

/**
 * Finishes an organization sign-in from the link mailed to its owner. The
 * link only works together with the session this browser holds for it.
 */
export async function confirmOrganizationSignIn(
  waiting: WaitingSignIn,
  token: string,
): Promise<LoginResult> {
  const { data } = await apiClient.post<OrgConfirmedSignInResponse>('/login/confirm', {
    refresh_token: waiting.pendingResponse.accessToken,
    token,
  });

  if (!data.mfa_enrollment_required) {
    return { kind: 'authenticated', response: waiting.pendingResponse };
  }

  return {
    kind: 'mfa_enrollment_required',
    orgSlug: waiting.orgSlug,
    pendingResponse: waiting.pendingResponse,
    sessionId: data.session_id,
  };
}

/** Finishes a tenant sign-in from the link mailed to its owner. */
export async function confirmTenantSignIn(
  context: TenantAuthContext,
  pendingResponse: LoginResponse,
  token: string,
): Promise<LoginResult> {
  const { data } = await apiClient.post<TenantConfirmedSignInResponse>(
    getTenantAuthEndpoint(context, 'sign-in/confirm'),
    { link: token, session_token: pendingResponse.accessToken },
  );

  if (!data.mfa_required) {
    return { kind: 'authenticated', response: pendingResponse };
  }

  return {
    kind: data.mfa_enrollment_required ? 'tenant_mfa_enrollment_required' : 'tenant_mfa_required',
    orgSlug: context.orgSlug,
    pendingResponse,
    sessionId: data.session_id,
    tenantSlug: context.tenantSlug,
  };
}

/**
 * Swaps the one-time code a single sign-on came back with for its session.
 * The session still waits on a second factor when the identity provider
 * reported none and the person has one here, or the workspace requires one.
 */
export async function exchangeTenantSsoCode(
  context: TenantAuthContext,
  code: string,
  state: string,
): Promise<LoginResult> {
  const response = await apiClient.post<TenantSessionResponse>(
    getTenantAuthEndpoint(context, 'sso/exchange'),
    { code, state } satisfies SsoExchangeRequest,
  );

  return tenantSessionResult(context, response.data);
}

/** Where a tenant sign-in stands: signed in, or owing a second factor. */
function tenantSessionResult(
  context: TenantAuthContext,
  session: TenantSessionResponse,
): LoginResult {
  const pendingResponse = sessionFor(context, session.session_id, session.refresh_token);

  if (!session.mfa_required) {
    return { kind: 'authenticated', response: pendingResponse };
  }

  return {
    kind: session.mfa_enrollment_required
      ? 'tenant_mfa_enrollment_required'
      : 'tenant_mfa_required',
    orgSlug: context.orgSlug,
    pendingResponse,
    sessionId: session.session_id,
    tenantSlug: context.tenantSlug,
  };
}

/**
 * A tenant session whose holder's name and email are not known yet; they are
 * filled in from `…/me` once it is stored.
 */
function sessionFor(
  context: TenantAuthContext,
  sessionId: string,
  refreshToken: string,
): LoginResponse {
  return {
    access: null,
    accessToken: refreshToken,
    user: {
      email: '',
      id: sessionId,
      name: '',
      organizationSlug: context.orgSlug,
      tenantSlug: context.tenantSlug,
    },
  };
}

export async function signUpToTenant(
  context: TenantAuthContext,
  signUp: TenantSignUp,
): Promise<void> {
  await apiClient.post<unknown>(getTenantAuthEndpoint(context, 'sign-up'), {
    display_name: signUp.displayName,
    email: signUp.email,
    password: signUp.password,
  } satisfies SignUpRequest);
}

export async function requestTenantPasswordReset(
  context: TenantAuthContext,
  email: string,
): Promise<void> {
  await apiClient.post<unknown>(getTenantAuthEndpoint(context, 'password/reset-request'), {
    email,
  } satisfies RequestTenantPasswordResetRequest);
}

/** Sets the new password. A second factor on the account must answer with `mfaCode`. */
export async function confirmPasswordReset(
  context: TenantAuthContext,
  token: string,
  newPassword: string,
  mfaCode?: string,
): Promise<PasswordBreach> {
  const response = await apiClient.post<PasswordSetResponse>(
    getTenantAuthEndpoint(context, 'password/reset-confirm'),
    {
      mfa_code: mfaCode,
      new_password: newPassword,
      token,
    } satisfies ConfirmPasswordResetRequest,
  );

  return toPasswordBreach(response.data.password_breach);
}

export async function requestOrganizationPasswordReset(email: string): Promise<void> {
  await apiClient.post<unknown>('/password/reset-request', {
    email,
  } satisfies RequestOrganizationPasswordResetRequest);
}

export async function confirmOrganizationPasswordReset(
  token: string,
  password: string,
  mfaCode?: string,
): Promise<void> {
  await apiClient.post<unknown>('/password/reset-confirm', {
    mfa_code: mfaCode,
    password,
    token,
  } satisfies ConfirmOrganizationPasswordResetRequest);
}

function toPasswordResetTokenStatus(response: TokenStatusResponse): PasswordResetTokenStatus {
  const policy = response.password_policy;

  return {
    passwordPolicy: policy ? { minLength: policy.min_length, require: policy.require } : null,
    status: response.status,
  };
}

export async function getPasswordResetTokenStatus(
  token: string,
): Promise<PasswordResetTokenStatus> {
  const response = await apiClient.post<TokenStatusResponse>('/password/reset-status', {
    token,
  } satisfies TokenStatusRequest);

  return toPasswordResetTokenStatus(response.data);
}

export async function getTenantPasswordResetTokenStatus(
  context: TenantAuthContext,
  token: string,
): Promise<PasswordResetTokenStatus> {
  const response = await apiClient.post<TokenStatusResponse>(
    getTenantAuthEndpoint(context, 'password/reset-status'),
    { token } satisfies TokenStatusRequest,
  );

  return toPasswordResetTokenStatus(response.data);
}

export async function resendPasswordReset(token: string): Promise<number> {
  const response = await apiClient.post<ResendTokenResponse>('/password/reset-resend', {
    token,
  } satisfies ResendTokenRequest);

  return response.data.retry_after_seconds;
}

export async function resendTenantPasswordReset(
  context: TenantAuthContext,
  token: string,
): Promise<number> {
  const response = await apiClient.post<ResendTokenResponse>(
    getTenantAuthEndpoint(context, 'password/reset-resend'),
    { token } satisfies ResendTokenRequest,
  );

  return response.data.retry_after_seconds;
}

export async function getVerificationTokenStatus(token: string): Promise<VerificationTokenStatus> {
  const response = await apiClient.post<VerificationTokenStatusResponse>(
    '/users/verify-email/status',
    { token } satisfies VerificationTokenStatusRequest,
  );

  return response.data.status;
}

export async function resendVerificationEmail(token: string): Promise<number> {
  const response = await apiClient.post<ResendVerificationEmailResponse>(
    '/users/verify-email/resend',
    { token } satisfies ResendVerificationEmailRequest,
  );

  return response.data.retry_after_seconds;
}

type OrgLogoutRequest = {
  session_id: string;
};

export async function logout(
  session: { orgSlug?: string | null; sessionId?: string | null },
  context?: TenantAuthContext,
) {
  if (context) {
    await apiClient.post<unknown>(
      `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
        context.tenantSlug,
      )}/auth/logout`,
    );

    return;
  }

  if (!session.orgSlug || !session.sessionId) {
    return;
  }

  await apiClient.post<unknown>(`/organizations/${encodeURIComponent(session.orgSlug)}/logout`, {
    session_id: session.sessionId,
  } satisfies OrgLogoutRequest);
}

type SwitchTenantResponse = {
  refresh_token: string;
  session_id: string;
  tenant_id: string;
};

/** Moves the session to a tenant the member holds a grant on. */
export async function switchOrganizationTenant(orgSlug: string, tenantId: string) {
  const response = await apiClient.post<SwitchTenantResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/switch-tenant`,
    { tenant_id: tenantId },
  );

  return {
    accessToken: response.data.refresh_token,
    sessionId: response.data.session_id,
    tenantId: response.data.tenant_id,
  };
}
