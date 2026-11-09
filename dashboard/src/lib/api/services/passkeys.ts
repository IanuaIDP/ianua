import { apiClient } from '@/lib/api/client';
import { createResource, getList } from '@/lib/api/crud';
import type {
  OrgLoginResponse,
  TenantAuthContext,
  TenantLoginAuthenticatedResponse,
} from '@/lib/api/services/auth';
import { toReenteredProofBody, type ReenteredProofBody } from '@/lib/api/reentered-proof';
import type { ReenteredProof } from '@/types/auth';
import type { Passkey, PasskeyAuthenticatorType, PasskeyCeremony } from '@/types/passkey';
import { formatBackendDate } from '@/utils/date';

type PasskeyChallengeResponse = {
  ceremony_id: string;
  challenge: string;
};

type PasskeyResponse = {
  authenticator_type: PasskeyAuthenticatorType;
  created_at: string;
  id: string;
  last_used_at?: string | null;
  name: string;
};

type PasskeyListResponse = {
  passkeys: PasskeyResponse[];
};

type RegisterPasskeyConfirmRequest = {
  ceremony_id: string;
  passkey_name: string;
  proof: ReenteredProofBody;
  response: string;
};

type LoginPasskeyBeginRequest = {
  email: string;
};

type ConfirmPasskeyLoginRequest = {
  ceremony_id: string;
  credential_id: string;
  response: string;
};

type RenamePasskeyRequest = {
  name: string;
};

function toPasskeyCeremony(response: PasskeyChallengeResponse): PasskeyCeremony {
  return {
    ceremonyId: response.ceremony_id,
    challenge: response.challenge,
  };
}

function toPasskey(response: PasskeyResponse): Passkey {
  return {
    authenticatorType: response.authenticator_type,
    created: formatBackendDate(response.created_at),
    id: response.id,
    lastUsed: response.last_used_at ? formatBackendDate(response.last_used_at) : null,
    name: response.name,
  };
}

function getOrgPasskeysEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/passkeys`;
}

function getTenantAuthEndpoint(context: TenantAuthContext, actionPath: string) {
  return `/organizations/${encodeURIComponent(context.orgSlug)}/tenants/${encodeURIComponent(
    context.tenantSlug,
  )}/auth/${actionPath}`;
}

export async function beginOrgPasskeyLogin(email: string): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, LoginPasskeyBeginRequest>(
    '/passkey/login',
    { email },
  );

  return toPasskeyCeremony(response);
}

export async function beginOrgPasskeyDiscovery(): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, Record<string, never>>(
    '/passkey/login/discover',
    {},
  );

  return toPasskeyCeremony(response);
}

export async function confirmOrgPasskeyLogin(
  ceremonyId: string,
  response: string,
  credentialId: string,
): Promise<OrgLoginResponse> {
  return createResource<OrgLoginResponse, ConfirmPasskeyLoginRequest>('/passkey/login/confirm', {
    ceremony_id: ceremonyId,
    credential_id: credentialId,
    response,
  });
}

export async function beginPasskeyRegistration(orgSlug: string): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, Record<string, never>>(
    `${getOrgPasskeysEndpoint(orgSlug)}/register`,
    {},
  );

  return toPasskeyCeremony(response);
}

export async function confirmPasskeyRegistration(
  orgSlug: string,
  ceremonyId: string,
  response: string,
  passkeyName: string,
  proof: ReenteredProof,
): Promise<void> {
  await createResource<unknown, RegisterPasskeyConfirmRequest>(
    `${getOrgPasskeysEndpoint(orgSlug)}/register/confirm`,
    {
      ceremony_id: ceremonyId,
      passkey_name: passkeyName,
      proof: toReenteredProofBody(proof),
      response,
    },
  );
}

export async function getPasskeys(orgSlug: string): Promise<Passkey[]> {
  const response = await getList<PasskeyListResponse>(getOrgPasskeysEndpoint(orgSlug));

  return response.passkeys.map(toPasskey);
}

export async function renamePasskey(
  orgSlug: string,
  passkeyId: string,
  name: string,
): Promise<void> {
  await apiClient.patch<unknown>(
    `${getOrgPasskeysEndpoint(orgSlug)}/${encodeURIComponent(passkeyId)}`,
    { name } satisfies RenamePasskeyRequest,
  );
}

export async function removePasskey(orgSlug: string, passkeyId: string): Promise<void> {
  await apiClient.delete(`${getOrgPasskeysEndpoint(orgSlug)}/${encodeURIComponent(passkeyId)}`);
}

export async function beginTenantPasskeyRegistration(
  context: TenantAuthContext,
): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, Record<string, never>>(
    getTenantAuthEndpoint(context, 'passkey/register'),
    {},
  );

  return toPasskeyCeremony(response);
}

export async function confirmTenantPasskeyRegistration(
  context: TenantAuthContext,
  ceremonyId: string,
  response: string,
  passkeyName: string,
  proof: ReenteredProof,
): Promise<void> {
  await createResource<unknown, RegisterPasskeyConfirmRequest>(
    getTenantAuthEndpoint(context, 'passkey/register/confirm'),
    {
      ceremony_id: ceremonyId,
      passkey_name: passkeyName,
      proof: toReenteredProofBody(proof),
      response,
    },
  );
}

export async function beginTenantPasskeyLogin(
  context: TenantAuthContext,
  email: string,
): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, LoginPasskeyBeginRequest>(
    getTenantAuthEndpoint(context, 'passkey/login'),
    { email },
  );

  return toPasskeyCeremony(response);
}

export async function beginTenantPasskeyDiscovery(
  context: TenantAuthContext,
): Promise<PasskeyCeremony> {
  const response = await createResource<PasskeyChallengeResponse, Record<string, never>>(
    getTenantAuthEndpoint(context, 'passkey/login/discover'),
    {},
  );

  return toPasskeyCeremony(response);
}

export async function confirmTenantPasskeyLogin(
  context: TenantAuthContext,
  ceremonyId: string,
  response: string,
  credentialId: string,
): Promise<TenantLoginAuthenticatedResponse> {
  return createResource<TenantLoginAuthenticatedResponse, ConfirmPasskeyLoginRequest>(
    getTenantAuthEndpoint(context, 'passkey/login/confirm'),
    { ceremony_id: ceremonyId, credential_id: credentialId, response },
  );
}

export async function getTenantPasskeys(context: TenantAuthContext): Promise<Passkey[]> {
  const response = await getList<PasskeyListResponse>(getTenantAuthEndpoint(context, 'passkeys'));

  return response.passkeys.map(toPasskey);
}

export async function renameTenantPasskey(
  context: TenantAuthContext,
  passkeyId: string,
  name: string,
): Promise<void> {
  await apiClient.patch<unknown>(
    `${getTenantAuthEndpoint(context, 'passkeys')}/${encodeURIComponent(passkeyId)}`,
    { name } satisfies RenamePasskeyRequest,
  );
}

export async function removeTenantPasskey(
  context: TenantAuthContext,
  passkeyId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantAuthEndpoint(context, 'passkeys')}/${encodeURIComponent(passkeyId)}`,
  );
}
