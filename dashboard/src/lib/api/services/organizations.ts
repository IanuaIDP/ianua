import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import type { TokenStatus } from '@/lib/api/services/auth';
import type {
  AccountSettingsEmailInput,
  AccountSettingsFullNameInput,
  AccountSettingsPasswordInput,
  OrganizationSettingsInput,
} from '@/schemas/settings-schemas';
import { useAuthStore } from '@/store/auth-store';
import type { Organization, OrganizationStatus } from '@/types/organization';
import { formatBackendDate } from '@/utils/date';
import { toReenteredProofBody, type ReenteredProofBody } from '@/lib/api/reentered-proof';
import type { ReenteredProof } from '@/types/auth';

export type OrganizationResponse = {
  contact_email?: string | null;
  created_at?: string | null;
  display_name?: string | null;
  id?: string | null;
  name?: string | null;
  slug?: string | null;
  status?: OrganizationStatus | null;
  tenant_count?: number | null;
};

export type BeginOrganizationMfaResponse = {
  otpauth_uri: string;
};

export type OrganizationMfaStatusResponse = {
  enabled: boolean;
  method?: string | null;
};

export type OrganizationMeResponse = {
  created_at?: string | null;
  display_name?: string | null;
  email?: string | null;
  id?: string | null;
  locale?: string | null;
  status?: string | null;
};

export type OrganizationMe = {
  createdAt: string;
  displayName: string;
  email: string;
  id: string;
  /** Preferred language tag, or `null` when the user inherits the organization default. */
  locale: string | null;
  status: string;
};

type UpdateOrganizationRequest = {
  contact_email: string;
  display_name: string;
  name: string;
};

type UpdateOrganizationMeRequest = {
  display_name: string;
};

type UpdateOrganizationMeLocaleRequest = {
  locale: string;
};

type RequestOrganizationEmailChangeRequest = {
  code?: string;
  new_email: string;
  password: string;
};

type ConfirmOrganizationEmailChangeRequest = {
  token: string;
};

type BeginOrganizationMfaRequest = {
  proof: ReenteredProofBody;
};

type OrganizationEmailChangeTokenStatusRequest = {
  token: string;
};

type OrganizationEmailChangeTokenStatusResponse = {
  status: TokenStatus;
};

type OrganizationEmailChangeResendRequest = {
  token: string;
};

type OrganizationEmailChangeResendResponse = {
  retry_after_seconds: number;
};

type ChangeOrganizationPasswordRequest = {
  new_password: string;
  old_password: string;
};

type ConfirmOrganizationMfaRequest = {
  code: string;
  session_id?: string;
};

/** What proves the person may turn their second factor off. */
export type OrganizationMfaProof = { code: string };

function getOrganizationEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}`;
}

function toOrganizationStatus(value?: OrganizationResponse['status']): OrganizationStatus {
  if (value === 'Closed' || value === 'Suspended') {
    return value;
  }

  return 'Active';
}

function toOrganization(response: OrganizationResponse): Organization {
  const slug = response.slug ?? '';
  const displayName = response.display_name ?? response.name ?? slug;

  return {
    contactEmail: response.contact_email ?? '',
    created: formatBackendDate(response.created_at),
    displayName,
    id: response.id ?? slug,
    name: response.name ?? displayName,
    slug,
    status: toOrganizationStatus(response.status),
    tenantsCount: response.tenant_count ?? 0,
  };
}

function toOrganizationMe(response: OrganizationMeResponse): OrganizationMe {
  return {
    createdAt: response.created_at ?? '',
    displayName: response.display_name ?? '',
    email: response.email ?? '',
    id: response.id ?? '',
    locale: response.locale ?? null,
    status: response.status ?? '',
  };
}

export async function getOrganization(orgSlug: string): Promise<Organization> {
  const response = await getList<OrganizationResponse>(getOrganizationEndpoint(orgSlug));

  return toOrganization(response);
}

export async function getOrganizationMe(orgSlug: string): Promise<OrganizationMe> {
  const response = await apiClient.get<OrganizationMeResponse>(
    `${getOrganizationEndpoint(orgSlug)}/me`,
  );

  return toOrganizationMe(response.data);
}

export async function updateOrganization(
  orgSlug: string,
  payload: OrganizationSettingsInput,
): Promise<Organization> {
  const response = await apiClient.patch<OrganizationResponse | null>(
    getOrganizationEndpoint(orgSlug),
    {
      contact_email: payload.contactEmail,
      display_name: payload.displayName,
      name: payload.name,
    } satisfies UpdateOrganizationRequest,
  );

  if (!response.data) {
    return getOrganization(orgSlug);
  }

  return toOrganization(response.data);
}

export async function updateOrganizationMe(
  orgSlug: string,
  payload: AccountSettingsFullNameInput,
): Promise<OrganizationMe> {
  const response = await apiClient.patch<OrganizationMeResponse | null>(
    `${getOrganizationEndpoint(orgSlug)}/me`,
    {
      display_name: payload.fullName,
    } satisfies UpdateOrganizationMeRequest,
  );

  if (!response.data) {
    return getOrganizationMe(orgSlug);
  }

  return toOrganizationMe(response.data);
}

/** Saves only the signed-in organization user's preferred language (BCP 47 tag, e.g. `uk-UA`). */
export async function updateOrganizationMeLocale(orgSlug: string, locale: string): Promise<void> {
  await apiClient.patch<unknown>(`${getOrganizationEndpoint(orgSlug)}/me`, {
    locale,
  } satisfies UpdateOrganizationMeLocaleRequest);
}

export async function suspendOrganization(orgSlug: string): Promise<void> {
  const accessToken = useAuthStore.getState().accessToken;
  const response = await fetch(`/api${getOrganizationEndpoint(orgSlug)}/suspend`, {
    cache: 'no-store',
    headers: {
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    method: 'POST',
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    const message =
      errorBody && typeof errorBody === 'object' && 'message' in errorBody
        ? errorBody.message
        : undefined;

    throw new Error(
      typeof message === 'string' && message.trim() ? message : 'Failed to suspend organization.',
    );
  }
}

export async function closeOrganization(orgSlug: string): Promise<void> {
  const accessToken = useAuthStore.getState().accessToken;
  const response = await fetch(`/api${getOrganizationEndpoint(orgSlug)}/close`, {
    cache: 'no-store',
    headers: {
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    method: 'POST',
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    const message =
      errorBody && typeof errorBody === 'object' && 'message' in errorBody
        ? errorBody.message
        : undefined;

    throw new Error(
      typeof message === 'string' && message.trim() ? message : 'Failed to close organization.',
    );
  }
}

export async function requestOrganizationEmailChange(
  orgSlug: string,
  payload: AccountSettingsEmailInput,
  proof: ReenteredProof,
): Promise<void> {
  await apiClient.post<unknown>(`${getOrganizationEndpoint(orgSlug)}/email/request-change`, {
    code: proof.code,
    new_email: payload.email,
    password: proof.password,
  } satisfies RequestOrganizationEmailChangeRequest);
}

export async function confirmOrganizationEmailChange(
  orgSlug: string,
  token: string,
): Promise<void> {
  await apiClient.post<unknown>(`${getOrganizationEndpoint(orgSlug)}/email/confirm-change`, {
    token,
  } satisfies ConfirmOrganizationEmailChangeRequest);
}

export async function getOrganizationEmailChangeTokenStatus(
  orgSlug: string,
  token: string,
): Promise<TokenStatus> {
  const response = await apiClient.post<OrganizationEmailChangeTokenStatusResponse>(
    `${getOrganizationEndpoint(orgSlug)}/email/change-status`,
    { token } satisfies OrganizationEmailChangeTokenStatusRequest,
  );

  return response.data.status;
}

export async function resendOrganizationEmailChange(
  orgSlug: string,
  token: string,
): Promise<number> {
  const response = await apiClient.post<OrganizationEmailChangeResendResponse>(
    `${getOrganizationEndpoint(orgSlug)}/email/change-resend`,
    { token } satisfies OrganizationEmailChangeResendRequest,
  );

  return response.data.retry_after_seconds;
}

export async function changeOrganizationPassword(
  orgSlug: string,
  payload: AccountSettingsPasswordInput,
): Promise<void> {
  await apiClient.post<unknown>(`${getOrganizationEndpoint(orgSlug)}/password/change`, {
    new_password: payload.newPassword,
    old_password: payload.currentPassword,
  } satisfies ChangeOrganizationPasswordRequest);
}

/**
 * Starts setting up a second factor. A signed-in member proves it is them
 * with `proof`; a sign-in waiting on the set-up has its session say so instead.
 */
export async function beginOrganizationMfa(
  orgSlug: string,
  proof?: ReenteredProof,
): Promise<BeginOrganizationMfaResponse> {
  const response = await apiClient.post<BeginOrganizationMfaResponse>(
    `${getOrganizationEndpoint(orgSlug)}/mfa/begin`,
    proof
      ? ({ proof: toReenteredProofBody(proof) } satisfies BeginOrganizationMfaRequest)
      : undefined,
  );

  return response.data;
}

export async function getOrganizationMfaStatus(
  orgSlug: string,
): Promise<OrganizationMfaStatusResponse> {
  const response = await apiClient.get<OrganizationMfaStatusResponse>(
    `${getOrganizationEndpoint(orgSlug)}/mfa/status`,
  );

  return response.data;
}

export async function disableOrganizationMfa(
  orgSlug: string,
  proof: OrganizationMfaProof,
): Promise<void> {
  await apiClient.delete<unknown>(`${getOrganizationEndpoint(orgSlug)}/mfa`, { data: proof });
}

/**
 * Confirms a new second factor and returns its recovery codes, shown once.
 * `completingSessionId` names a sign-in that was waiting on the set-up; it
 * is finished by it.
 */
export async function confirmOrganizationMfa(
  orgSlug: string,
  code: string,
  completingSessionId?: string,
): Promise<string[]> {
  const response = await apiClient.post<{ recovery_codes: string[] }>(
    `${getOrganizationEndpoint(orgSlug)}/mfa/confirm`,
    { code, session_id: completingSessionId } satisfies ConfirmOrganizationMfaRequest,
  );

  return response.data.recovery_codes;
}
