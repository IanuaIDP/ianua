import { apiClient } from '@/lib/api/client';
import { getList } from '@/lib/api/crud';
import type { CloudCredentialInput } from '@/schemas/cloud-schemas';
import type {
  CloudAccount,
  CloudAccountState,
  CloudAccountStatus,
  CloudNetwork,
  CloudProviderId,
  ConnectionInstructions,
} from '@/types/cloud-account';
import { formatBackendDate } from '@/utils/date';

type CloudAccountResponse = {
  account?: string | null;
  created_at?: string | null;
  failure_reason?: string | null;
  provider?: CloudProviderId | null;
  revocable_by_you?: boolean | null;
  state?: CloudAccountState | null;
  usable?: boolean | null;
  verified_at?: string | null;
};

type ConnectionInstructionsResponse = {
  console_url?: string | null;
  external_id?: string | null;
  provider?: CloudProviderId | null;
  steps?: string[] | null;
};

type CloudNetworkResponse = {
  handle?: string | null;
  name?: string | null;
  region?: string | null;
};

type CredentialRequest =
  | { kind: 'aws_assume_role'; role_arn: string }
  | { client_email: string; key: string; kind: 'gcp_service_account' }
  | { client_id: string; directory_id: string; kind: 'azure_service_principal'; secret: string }
  | { kind: 'digitalocean_token'; token: string }
  | { ca_certificate: string; kind: 'kubernetes_service_account'; server: string; token: string };

const statusByState: Record<CloudAccountState, CloudAccountStatus> = {
  awaiting_credential: 'Pending',
  awaiting_verification: 'PendingVerification',
  failed: 'Failed',
  verified: 'Verified',
};

function getCloudAccountsEndpoint(orgSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/cloud-accounts`;
}

function getCloudAccountEndpoint(orgSlug: string, provider: CloudProviderId) {
  return `${getCloudAccountsEndpoint(orgSlug)}/${encodeURIComponent(provider)}`;
}

function toCloudAccount(response: CloudAccountResponse): CloudAccount {
  const state = response.state ?? 'awaiting_credential';

  return {
    account: response.account ?? undefined,
    connected: formatBackendDate(response.created_at),
    failureReason: response.failure_reason ?? undefined,
    provider: response.provider ?? 'aws',
    revocableByYou: response.revocable_by_you ?? false,
    status: statusByState[state] ?? 'Pending',
    usable: response.usable ?? false,
    verified: formatBackendDate(response.verified_at),
  };
}

function toCredentialRequest(payload: CloudCredentialInput): CredentialRequest {
  switch (payload.kind) {
    case 'aws_assume_role':
      return { kind: payload.kind, role_arn: payload.roleArn.trim() };
    case 'gcp_service_account':
      return {
        client_email: payload.clientEmail.trim(),
        key: payload.key,
        kind: payload.kind,
      };
    case 'azure_service_principal':
      return {
        client_id: payload.clientId.trim(),
        directory_id: payload.directoryId.trim(),
        kind: payload.kind,
        secret: payload.secret,
      };
    case 'digitalocean_token':
      return { kind: payload.kind, token: payload.token.trim() };
    case 'kubernetes_service_account':
      return {
        ca_certificate: payload.caCertificate.trim(),
        kind: payload.kind,
        server: payload.server.trim(),
        token: payload.token.trim(),
      };
  }
}

export async function getCloudAccounts(orgSlug: string): Promise<CloudAccount[]> {
  const response = await getList<CloudAccountResponse[]>(getCloudAccountsEndpoint(orgSlug));

  return (response ?? []).map(toCloudAccount);
}

export async function beginCloudConnection(
  orgSlug: string,
  provider: CloudProviderId,
): Promise<ConnectionInstructions> {
  const response = await apiClient.post<ConnectionInstructionsResponse>(
    getCloudAccountEndpoint(orgSlug, provider),
  );

  return {
    consoleUrl: response.data.console_url ?? undefined,
    externalId: response.data.external_id ?? '',
    provider: response.data.provider ?? provider,
    steps: response.data.steps ?? [],
  };
}

export async function submitCloudCredential(
  orgSlug: string,
  provider: CloudProviderId,
  payload: CloudCredentialInput,
): Promise<CloudAccount> {
  const response = await apiClient.put<CloudAccountResponse>(
    `${getCloudAccountEndpoint(orgSlug, provider)}/credential`,
    toCredentialRequest(payload),
  );

  return toCloudAccount(response.data);
}

export async function verifyCloudAccount(
  orgSlug: string,
  provider: CloudProviderId,
): Promise<CloudAccount> {
  const response = await apiClient.post<CloudAccountResponse>(
    `${getCloudAccountEndpoint(orgSlug, provider)}/verify`,
  );

  return toCloudAccount(response.data);
}

export async function disconnectCloudAccount(
  orgSlug: string,
  provider: CloudProviderId,
): Promise<void> {
  await apiClient.delete(getCloudAccountEndpoint(orgSlug, provider));
}

export async function getCloudNetworks(
  orgSlug: string,
  provider: CloudProviderId,
  region: string,
): Promise<CloudNetwork[]> {
  const response = await getList<CloudNetworkResponse[]>(
    `${getCloudAccountEndpoint(orgSlug, provider)}/networks`,
    { params: { region } },
  );

  return (response ?? []).map((network) => ({
    handle: network.handle ?? '',
    name: network.name ?? network.handle ?? '',
    region: network.region ?? region,
  }));
}
