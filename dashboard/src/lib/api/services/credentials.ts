import { apiClient } from '@/lib/api/client';
import type {
  AttestationMethod,
  Credential,
  CredentialAction,
  CredentialAlgorithm,
  CredentialAttestation,
  CredentialStatus,
} from '@/types/credential';

type CredentialAttestationResponse = {
  method: string;
  subject: string;
};

type CredentialResponse = {
  algorithm: string;
  attestation?: CredentialAttestationResponse | null;
  created_at: string;
  expires_at?: string | null;
  grace_ends_at?: string | null;
  grace_period_seconds?: number | null;
  id: string;
  kid: string;
  public_key: string;
  rotated_at?: string | null;
  status: string;
};

type EnrolKeyRequest = {
  algorithm: CredentialAlgorithm;
  public_key: string;
};

type MintCredentialRequest = EnrolKeyRequest & {
  expires_in_seconds?: number | null;
};

function toCredentialAlgorithm(value: string): CredentialAlgorithm {
  if (value === 'EdDSA' || value === 'ES256' || value === 'RS256') {
    return value;
  }

  return 'ES256';
}

function toCredentialStatus(value: string): CredentialStatus {
  const normalized = value?.toLowerCase();

  if (normalized === 'rotated') {
    return 'Rotated';
  }

  if (normalized === 'revoked') {
    return 'Revoked';
  }

  return 'Active';
}

function toAttestationMethod(value: string): AttestationMethod | null {
  const normalized = value?.toLowerCase();

  if (
    normalized === 'aws' ||
    normalized === 'gcp' ||
    normalized === 'spiffe' ||
    normalized === 'tpm'
  ) {
    return normalized;
  }

  return null;
}

function toCredentialAttestation(
  response?: CredentialAttestationResponse | null,
): CredentialAttestation | null {
  if (!response) {
    return null;
  }

  const method = toAttestationMethod(response.method);

  if (!method) {
    return null;
  }

  return { method, subject: response.subject };
}

function toCredential(response: CredentialResponse): Credential {
  return {
    algorithm: toCredentialAlgorithm(response.algorithm),
    attestation: toCredentialAttestation(response.attestation),
    createdAt: response.created_at,
    expiresAt: response.expires_at ?? null,
    graceEndsAt: response.grace_ends_at ?? null,
    gracePeriodSeconds: response.grace_period_seconds ?? null,
    id: response.id,
    kid: response.kid,
    publicKey: response.public_key,
    rotatedAt: response.rotated_at ?? null,
    status: toCredentialStatus(response.status),
  };
}

function getAgentCredentialsEndpoint(orgSlug: string, tenantSlug: string, agentId: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/agents/${encodeURIComponent(agentId)}/credentials`;
}

export async function getAgentCredentials(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
): Promise<Credential[]> {
  const response = await apiClient.get<CredentialResponse[]>(
    getAgentCredentialsEndpoint(orgSlug, tenantSlug, agentId),
  );

  return response.data.map(toCredential);
}

export async function mintAgentCredential(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  algorithm: CredentialAlgorithm,
  publicKey: string,
  expiresInSeconds?: number,
): Promise<Credential> {
  const response = await apiClient.post<CredentialResponse>(
    getAgentCredentialsEndpoint(orgSlug, tenantSlug, agentId),
    {
      algorithm,
      expires_in_seconds: expiresInSeconds ?? null,
      public_key: publicKey,
    } satisfies MintCredentialRequest,
  );

  return toCredential(response.data);
}

export async function rotateAgentCredential(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  credentialId: string,
  algorithm: CredentialAlgorithm,
  publicKey: string,
): Promise<Credential> {
  const response = await apiClient.post<CredentialResponse>(
    `${getAgentCredentialsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(credentialId)}/rotate`,
    { algorithm, public_key: publicKey } satisfies EnrolKeyRequest,
  );

  return toCredential(response.data);
}

export async function revokeAgentCredential(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  credentialId: string,
): Promise<void> {
  await apiClient.delete<unknown>(
    `${getAgentCredentialsEndpoint(orgSlug, tenantSlug, agentId)}/${encodeURIComponent(credentialId)}`,
  );
}

export async function executeAgentCredentialAction(
  orgSlug: string,
  tenantSlug: string,
  agentId: string,
  credential: Credential,
  action: CredentialAction,
): Promise<void> {
  if (action === 'Revoke') {
    await revokeAgentCredential(orgSlug, tenantSlug, agentId, credential.id);
  }
}
