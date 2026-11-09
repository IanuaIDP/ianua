import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import {
  toPasswordBreach,
  type PasswordBreachResponse,
  type TokenStatus,
  type VerificationTokenStatus,
} from '@/lib/api/services/auth';
import type { AddTenantUserInput } from '@/schemas/tenant-user-schemas';
import { formatBackendDate } from '@/utils/date';
import { getInitials } from '@/utils/initials';
import type { PasswordBreach } from '@/types/auth';
import type { CharacterRequirements, PasswordPolicy } from '@/types/auth-config';
import type { UserAttributeValues } from '@/types/user-attribute';
import type {
  TenantUser,
  TenantUserAction,
  TenantUserList,
  TenantUserProfile,
  TenantUserRole,
  TenantUserSortDirection,
  TenantUserSortField,
  TenantUserStatus,
} from '@/types/tenant-user';

type TenantUserProfileResponse = {
  department?: string | null;
  employee_number?: string | null;
  external_id?: string | null;
  family_name?: string | null;
  given_name?: string | null;
  manager_id?: string | null;
  phone_number?: string | null;
  picture?: string | null;
  preferred_username?: string | null;
};

export type TenantUserResponse = {
  attributes?: UserAttributeValues | null;
  created_at?: string | null;
  display_name?: string | null;
  email?: string | null;
  email_verified?: boolean | null;
  id?: string | null;
  invitation_status?: string | null;
  invited_role?: TenantUserRole | null;
  joined_at?: string | null;
  last_login_at?: string | null;
  profile?: TenantUserProfileResponse | null;
  roles?: TenantUserRole[] | null;
  status?: TenantUserStatus | null;
  updated_at?: string | null;
};

function toTenantUserStatus(response: TenantUserResponse): TenantUserStatus {
  if (response.invitation_status === 'Expired') {
    return 'InvitationExpired';
  }

  return response.status ?? 'Invited';
}

type TenantUsersResponse = {
  items: TenantUserResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantUsersParams = {
  after?: string;
  /**
   * Custom-field filters, already written as the API's terms —
   * `app.department:is:sales`. Repeated, and every one must hold.
   */
  attributeFilters?: string[];
  /** A custom field to order by, as `attr:app.salary` or `-attr:app.salary`. */
  attributeSort?: string;
  limit?: number;
  sortDirection?: TenantUserSortDirection;
  sortField?: TenantUserSortField;
  status?: TenantUserStatus;
};

type InviteTenantUserRequest = {
  display_name: string;
  email: string;
  message: string;
  role_id: string;
};

type CreateTenantUserRequest = {
  auto_verify: boolean;
  display_name: string;
  email: string;
  password: string;
  role_ids: string[];
};

type UpdateTenantUserStatusRequest = {
  status: 'Locked' | 'Active';
};

type ResetTenantUserPasswordRequest = {
  password: string;
};

type ResetTenantUserPasswordResponse = {
  new_password: string;
  password_breach: PasswordBreachResponse;
};

export type TenantUserPasswordReset = {
  breach: PasswordBreach;
  newPassword: string;
};

type UpdateTenantUserProfileRequest = {
  display_name?: string;
  email?: string;
};

export type UpdateTenantUserProfilePayload = {
  displayName?: string;
  email?: string;
};

export type AcceptTenantUserInvitationRequest = {
  password?: string;
  token: string;
};

function toTenantUserProfile(response?: TenantUserProfileResponse | null): TenantUserProfile {
  return {
    department: response?.department ?? null,
    employeeNumber: response?.employee_number ?? null,
    externalId: response?.external_id ?? null,
    familyName: response?.family_name ?? null,
    givenName: response?.given_name ?? null,
    managerId: response?.manager_id ?? null,
    phoneNumber: response?.phone_number ?? null,
    picture: response?.picture ?? null,
    preferredUsername: response?.preferred_username ?? null,
  };
}

function toTenantUser(response: TenantUserResponse): TenantUser {
  const email = response.email ?? '';
  const displayName = response.display_name || email || 'Unknown user';

  return {
    attributes: response.attributes ?? {},
    avatarInitial: getInitials(displayName),
    created: formatBackendDate(response.created_at),
    displayName,
    email,
    emailVerified: Boolean(response.email_verified),
    id: response.id ?? email,
    invitedRole: response.invited_role ?? null,
    joined: response.joined_at ? formatBackendDate(response.joined_at) : null,
    lastLogin: formatBackendDate(response.last_login_at),
    profile: toTenantUserProfile(response.profile),
    roles: response.roles ?? [],
    status: toTenantUserStatus(response),
    updated: formatBackendDate(response.updated_at),
  };
}

export async function getTenantUsers(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantUsersParams,
): Promise<TenantUserList> {
  // A custom field and a column of the user row are ordered by different
  // machinery, so only one of the two ever reaches `sort`.
  const sort = params?.attributeSort ?? buildSortParam(params?.sortField, params?.sortDirection);

  // `attr` repeats, and the shared params helper takes scalars only — so the
  // terms are appended to the URL rather than widening it for one call site.
  const terms = (params?.attributeFilters ?? [])
    .map((term) => `attr=${encodeURIComponent(term)}`)
    .join('&');
  const endpoint = `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/users${terms ? `?${terms}` : ''}`;

  const response = await getList<TenantUsersResponse>(endpoint, {
    params: {
      after: params?.after,
      limit: params?.limit,
      sort,
      status: params?.status,
    },
  });

  return {
    items: response.items.map(toTenantUser),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

function getTenantUsersEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/users`;
}

type InvitedTenantUserResponse = {
  accept_link?: string | null;
  id: string;
};

export type InvitedTenantUser = {
  /** The link to hand over by hand, on an install that cannot send mail. */
  acceptLink: string | null;
  id: string;
};

export async function inviteTenantUser(
  orgSlug: string,
  tenantSlug: string,
  payload: AddTenantUserInput,
): Promise<InvitedTenantUser> {
  const response = await createResource<InvitedTenantUserResponse, InviteTenantUserRequest>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/invite`,
    {
      display_name: payload.fullName,
      email: payload.email,
      message: '',
      role_id: payload.roleIds[0] ?? '',
    },
  );

  return { acceptLink: response.accept_link ?? null, id: response.id };
}

export async function acceptTenantUserInvitation(
  orgSlug: string,
  tenantSlug: string,
  payload: AcceptTenantUserInvitationRequest,
): Promise<void> {
  await createResource<unknown, AcceptTenantUserInvitationRequest>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/accept-invitation`,
    payload,
  );
}

type VerifyTenantUserEmailRequest = {
  token: string;
};

export async function verifyTenantUserEmail(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<void> {
  await apiClient.post<unknown>(`${getTenantUsersEndpoint(orgSlug, tenantSlug)}/verify-email`, {
    token,
  } satisfies VerifyTenantUserEmailRequest);
}

type TenantVerificationTokenStatusRequest = {
  token: string;
};

type TenantVerificationTokenStatusResponse = {
  status: VerificationTokenStatus;
};

export async function getTenantVerificationTokenStatus(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<VerificationTokenStatus> {
  const response = await apiClient.post<TenantVerificationTokenStatusResponse>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/verify-email/status`,
    { token } satisfies TenantVerificationTokenStatusRequest,
  );

  return response.data.status;
}

type TenantTokenStatusRequest = {
  token: string;
};

type TenantTokenStatusResponse = {
  status: TokenStatus;
};

type TenantInvitationStatusResponse = TenantTokenStatusResponse & {
  password_policy?: { min_length: number; require: CharacterRequirements };
};

export type TenantInvitationStatus = {
  passwordPolicy: PasswordPolicy | null;
  status: TokenStatus;
};

type TenantResendTokenRequest = {
  token: string;
};

type TenantResendTokenResponse = {
  retry_after_seconds: number;
};

export async function getTenantInvitationTokenStatus(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<TenantInvitationStatus> {
  const response = await apiClient.post<TenantInvitationStatusResponse>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/invitation-status`,
    { token } satisfies TenantTokenStatusRequest,
  );
  const policy = response.data.password_policy;

  return {
    passwordPolicy: policy ? { minLength: policy.min_length, require: policy.require } : null,
    status: response.data.status,
  };
}

export async function resendTenantInvitation(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<number> {
  const response = await apiClient.post<TenantResendTokenResponse>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/invitation-resend`,
    { token } satisfies TenantResendTokenRequest,
  );

  return response.data.retry_after_seconds;
}

export async function getTenantEmailChangeTokenStatus(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<TokenStatus> {
  const response = await apiClient.post<TenantTokenStatusResponse>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/email/change-status`,
    { token } satisfies TenantTokenStatusRequest,
  );

  return response.data.status;
}

/** Applies the email change the mailed link confirms. */
export async function confirmTenantEmailChange(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<void> {
  await apiClient.post<unknown>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/email/confirm-change`,
    { token } satisfies TenantTokenStatusRequest,
  );
}

export async function resendTenantEmailChange(
  orgSlug: string,
  tenantSlug: string,
  token: string,
): Promise<number> {
  const response = await apiClient.post<TenantResendTokenResponse>(
    `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/email/change-resend`,
    { token } satisfies TenantResendTokenRequest,
  );

  return response.data.retry_after_seconds;
}

type CreatedTenantUserResponse = {
  generated_password?: string | null;
  id: string;
  password_breach?: PasswordBreachResponse | null;
};

export type CreatedTenantUser = {
  breach: PasswordBreach | null;
  generatedPassword: string | null;
  id: string;
};

export async function createTenantUser(
  orgSlug: string,
  tenantSlug: string,
  payload: AddTenantUserInput,
): Promise<CreatedTenantUser> {
  const response = await createResource<CreatedTenantUserResponse, CreateTenantUserRequest>(
    getTenantUsersEndpoint(orgSlug, tenantSlug),
    {
      auto_verify: payload.autoVerify,
      display_name: payload.fullName,
      email: payload.email,
      password: payload.password ?? '',
      role_ids: payload.roleIds,
    },
  );

  return {
    breach: response.password_breach ? toPasswordBreach(response.password_breach) : null,
    generatedPassword: response.generated_password ?? null,
    id: response.id,
  };
}

function getTenantUserEndpoint(orgSlug: string, tenantSlug: string, userId: string) {
  return `${getTenantUsersEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(userId)}`;
}

export async function updateTenantUserStatus(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
  status: UpdateTenantUserStatusRequest['status'],
): Promise<void> {
  await apiClient.post<unknown>(`${getTenantUserEndpoint(orgSlug, tenantSlug, userId)}/status`, {
    status,
  } satisfies UpdateTenantUserStatusRequest);
}

export async function revokeTenantUserInvitation(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
): Promise<void> {
  await apiClient.post<unknown>(
    `${getTenantUserEndpoint(orgSlug, tenantSlug, userId)}/revoke-invitation`,
  );
}

type InvitationLinkResponse = {
  accept_link?: string | null;
};

/** Sends the invitation again; returns its link when the install cannot mail it. */
export async function resendTenantUserInvitation(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
): Promise<string | null> {
  const response = await apiClient.post<InvitationLinkResponse | null>(
    `${getTenantUserEndpoint(orgSlug, tenantSlug, userId)}/resend-invitation`,
  );

  return response.data?.accept_link ?? null;
}

export async function deleteTenantUser(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
): Promise<void> {
  await apiClient.delete(getTenantUserEndpoint(orgSlug, tenantSlug, userId));
}

export async function updateTenantUserProfile(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
  payload: UpdateTenantUserProfilePayload,
): Promise<void> {
  await apiClient.patch<unknown>(getTenantUserEndpoint(orgSlug, tenantSlug, userId), {
    ...(payload.displayName !== undefined ? { display_name: payload.displayName } : {}),
    ...(payload.email !== undefined ? { email: payload.email } : {}),
  } satisfies UpdateTenantUserProfileRequest);
}

export async function sendTenantUserVerification(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
): Promise<void> {
  await apiClient.post<unknown>(
    `${getTenantUserEndpoint(orgSlug, tenantSlug, userId)}/send-verification`,
  );
}

export async function resetTenantUserPassword(
  orgSlug: string,
  tenantSlug: string,
  userId: string,
  password: string,
): Promise<TenantUserPasswordReset> {
  const response = await apiClient.post<ResetTenantUserPasswordResponse>(
    `${getTenantUserEndpoint(orgSlug, tenantSlug, userId)}/reset-password`,
    { password } satisfies ResetTenantUserPasswordRequest,
  );

  return {
    breach: toPasswordBreach(response.data.password_breach),
    newPassword: response.data.new_password,
  };
}

export async function executeTenantUserAction(
  orgSlug: string,
  tenantSlug: string,
  user: TenantUser,
  action: TenantUserAction,
): Promise<string | null> {
  if (action === 'Lock') {
    await updateTenantUserStatus(orgSlug, tenantSlug, user.id, 'Locked');
    return null;
  }

  if (action === 'Restore Access') {
    await updateTenantUserStatus(orgSlug, tenantSlug, user.id, 'Active');
    return null;
  }

  if (action === 'Delete Forever') {
    await deleteTenantUser(orgSlug, tenantSlug, user.id);
    return null;
  }

  if (action === 'Revoke Invitation') {
    await revokeTenantUserInvitation(orgSlug, tenantSlug, user.id);
    return null;
  }

  if (action === 'Resend Invitation') {
    return resendTenantUserInvitation(orgSlug, tenantSlug, user.id);
  }

  throw new Error(`${action} is not available yet.`);
}
