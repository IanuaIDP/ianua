import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import type { TokenStatus } from '@/lib/api/services/auth';
import type { AddTeamMemberInput } from '@/schemas/team-member-schemas';
import { formatBackendDate } from '@/utils/date';
import { getInitials } from '@/utils/initials';
import type { OrgRole } from '@/types/auth';
import type { CharacterRequirements, PasswordPolicy } from '@/types/auth-config';
import type {
  TeamMember,
  TeamMemberAction,
  TeamMemberList,
  TeamMemberSortDirection,
  TeamMemberSortField,
  TeamMemberStatus,
} from '@/types/team';
import { isNotAvailable } from '@/utils/not-available';

export type TeamMemberResponse = {
  created_at?: string | null;
  invitation_status?: string | null;
  joined_at?: string | null;
  display_name?: string | null;
  id?: string | null;
  role?: OrgRole | null;
  status?: TeamMemberStatus | null;
  email?: string | null;
};

function toTeamMemberStatus(response: TeamMemberResponse): TeamMemberStatus {
  if (response.invitation_status === 'Expired') {
    return 'InvitationExpired';
  }

  return response.status ?? 'Invited';
}

type TeamMembersResponse = {
  items: TeamMemberResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTeamMembersParams = {
  after?: string;
  limit?: number;
  sortDirection?: TeamMemberSortDirection;
  sortField?: TeamMemberSortField;
  status?: TeamMemberStatus;
};

type InviteTeamMemberRequest = {
  display_name: string;
  email: string;
  role: OrgRole;
};

type CreateTeamMemberRequest = InviteTeamMemberRequest & {
  auto_verify: boolean;
  password: string;
};

type UpdateTeamMemberStatusRequest = {
  status: 'Locked' | 'Active';
};

type ChangeTeamMemberRoleRequest = {
  role: OrgRole;
};

type ResetTeamMemberPasswordRequest = {
  password: string;
};

export type AcceptTeamMemberInvitationRequest = {
  password: string;
  token: string;
};

type VerifyOrganizationUserEmailRequest = {
  token: string;
};

type SendOrganizationVerificationEmailRequest = {
  email: string;
};

type TeamInvitationTokenStatusRequest = {
  token: string;
};

type TeamInvitationTokenStatusResponse = {
  password_policy?: { min_length: number; require: CharacterRequirements };
  status: TokenStatus;
};

export type TeamInvitationStatus = {
  passwordPolicy: PasswordPolicy | null;
  status: TokenStatus;
};

type TeamInvitationResendRequest = {
  token: string;
};

type TeamInvitationResendResponse = {
  retry_after_seconds: number;
};

function toTeamMember(response: TeamMemberResponse): TeamMember {
  const email = response.email ?? '';
  const name = response.display_name || email || 'Unknown member';
  const joined = formatBackendDate(response.joined_at);

  return {
    created: formatBackendDate(response.created_at),
    joined: isNotAvailable(joined) ? '-' : joined,
    id: response.id ?? email,
    name,
    role: response.role ?? 'Member',
    status: toTeamMemberStatus(response),
    email,
    avatarInitial: getInitials(name),
  };
}

export async function getTeamMembers(
  orgSlug: string,
  params?: GetTeamMembersParams,
): Promise<TeamMemberList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<TeamMembersResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/users`,
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
        status: params?.status,
      },
    },
  );

  return {
    items: response.items.map(toTeamMember),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

type InvitedTeamMemberResponse = {
  accept_link?: string | null;
  id: string;
};

/** Returns the link to hand over by hand, on an install that cannot send mail. */
export async function inviteTeamMember(
  orgSlug: string,
  payload: AddTeamMemberInput,
): Promise<string | null> {
  const response = await createResource<InvitedTeamMemberResponse, InviteTeamMemberRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/users`,
    {
      display_name: payload.fullName,
      email: payload.email,
      role: payload.role,
    },
  );

  return response.accept_link ?? null;
}

export async function acceptTeamMemberInvitation(
  orgSlug: string,
  payload: AcceptTeamMemberInvitationRequest,
): Promise<void> {
  await createResource<unknown, AcceptTeamMemberInvitationRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/accept-invitation`,
    payload,
  );
}

export async function getTeamInvitationTokenStatus(
  orgSlug: string,
  token: string,
): Promise<TeamInvitationStatus> {
  const response = await apiClient.post<TeamInvitationTokenStatusResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/invitation-status`,
    { token } satisfies TeamInvitationTokenStatusRequest,
  );
  const policy = response.data.password_policy;

  return {
    passwordPolicy: policy ? { minLength: policy.min_length, require: policy.require } : null,
    status: response.data.status,
  };
}

export async function resendTeamInvitation(orgSlug: string, token: string): Promise<number> {
  const response = await apiClient.post<TeamInvitationResendResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/invitation-resend`,
    { token } satisfies TeamInvitationResendRequest,
  );

  return response.data.retry_after_seconds;
}

export async function verifyOrganizationUserEmail(orgSlug: string, token: string): Promise<void> {
  await createResource<unknown, VerifyOrganizationUserEmailRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/verify-email`,
    { token },
  );
}

export async function sendOrganizationVerificationEmail(
  orgSlug: string,
  email: string,
): Promise<void> {
  await createResource<unknown, SendOrganizationVerificationEmailRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/send-verification`,
    { email },
  );
}

export async function createTeamMember(
  orgSlug: string,
  payload: AddTeamMemberInput,
): Promise<void> {
  await createResource<unknown, CreateTeamMemberRequest>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/create`,
    {
      auto_verify: payload.autoVerify,
      display_name: payload.fullName,
      email: payload.email,
      password: payload.password ?? '',
      role: payload.role,
    },
  );
}

function getTeamMemberEndpoint(orgSlug: string, userId: number | string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/users/${encodeURIComponent(String(userId))}`;
}

export async function updateTeamMemberStatus(
  orgSlug: string,
  userId: number | string,
  status: UpdateTeamMemberStatusRequest['status'],
): Promise<void> {
  await apiClient.patch<unknown>(`${getTeamMemberEndpoint(orgSlug, userId)}/status`, {
    status,
  } satisfies UpdateTeamMemberStatusRequest);
}

export async function changeTeamMemberRole(
  orgSlug: string,
  userId: number | string,
  role: OrgRole,
): Promise<void> {
  await apiClient.patch<unknown>(`${getTeamMemberEndpoint(orgSlug, userId)}/role`, {
    role,
  } satisfies ChangeTeamMemberRoleRequest);
}

type MemberAccessResponse = {
  role: OrgRole;
  tenants: { display_name: string; roles: string[]; slug: string }[];
};

/** The roles a member holds in each tenant they can reach, keyed by tenant slug. */
export type MemberTenantRoles = Record<string, string[]>;

/** The names of the roles a member can be given in one tenant, for the access form. */
export async function getGrantableRoles(orgSlug: string, tenantSlug: string): Promise<string[]> {
  const response = await getList<{ items: { name: string }[] }>(
    `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/grantable-roles`,
    { params: { limit: 100 } },
  );

  return response.items.map((role) => role.name);
}

export async function getMemberTenantRoles(
  orgSlug: string,
  userId: number | string,
): Promise<MemberTenantRoles> {
  const response = await apiClient.get<MemberAccessResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/users/${encodeURIComponent(String(userId))}/access`,
  );

  return Object.fromEntries(response.data.tenants.map((tenant) => [tenant.slug, tenant.roles]));
}

export async function setMemberTenantRoles(
  orgSlug: string,
  userId: number | string,
  tenantSlug: string,
  roles: string[],
): Promise<void> {
  await apiClient.put(
    `/organizations/${encodeURIComponent(orgSlug)}/users/${encodeURIComponent(
      String(userId),
    )}/tenants/${encodeURIComponent(tenantSlug)}`,
    { roles },
  );
}

export async function deleteTeamMember(orgSlug: string, userId: number | string): Promise<void> {
  await apiClient.delete(getTeamMemberEndpoint(orgSlug, userId));
}

export async function resetTeamMemberPassword(
  orgSlug: string,
  userId: number | string,
  password: string,
): Promise<void> {
  await apiClient.post<unknown>(`${getTeamMemberEndpoint(orgSlug, userId)}/reset-password`, {
    password,
  } satisfies ResetTeamMemberPasswordRequest);
}

/**
 * Turns off a member's second factor for when they lost it and their
 * recovery codes. They are signed out everywhere and emailed.
 */
export async function resetTeamMemberMfa(orgSlug: string, userId: number | string): Promise<void> {
  await apiClient.post<unknown>(`${getTeamMemberEndpoint(orgSlug, userId)}/mfa/reset`);
}

export async function revokeTeamMemberInvitation(
  orgSlug: string,
  userId: number | string,
): Promise<void> {
  await apiClient.post<unknown>(`${getTeamMemberEndpoint(orgSlug, userId)}/revoke-invitation`);
}

/** Sends the invitation again; returns its link when the install cannot mail it. */
export async function resendTeamMemberInvitation(
  orgSlug: string,
  userId: number | string,
): Promise<string | null> {
  const response = await apiClient.post<{ accept_link?: string | null } | null>(
    `${getTeamMemberEndpoint(orgSlug, userId)}/resend-invitation`,
  );

  return response.data?.accept_link ?? null;
}

export async function executeTeamMemberAction(
  orgSlug: string,
  member: TeamMember,
  action: TeamMemberAction,
): Promise<string | null> {
  if (action === 'Lock') {
    await updateTeamMemberStatus(orgSlug, member.id, 'Locked');
    return null;
  }

  if (action === 'Restore Access') {
    await updateTeamMemberStatus(orgSlug, member.id, 'Active');
    return null;
  }

  if (action === 'Delete Forever') {
    await deleteTeamMember(orgSlug, member.id);
    return null;
  }

  if (action === 'Revoke Invitation') {
    await revokeTeamMemberInvitation(orgSlug, member.id);
    return null;
  }

  if (action === 'Reset Second Factor') {
    await resetTeamMemberMfa(orgSlug, member.id);
    return null;
  }

  if (action === 'Resend Invitation') {
    return resendTeamMemberInvitation(orgSlug, member.id);
  }

  return null;
}
