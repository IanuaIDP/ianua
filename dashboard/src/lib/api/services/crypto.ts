import { apiClient } from '@/lib/api/client';
import { isAxiosError } from 'axios';
import type {
  PlanCryptoMigrationInput,
  RollbackCryptoMigrationInput,
  RotateCryptoKeyInput,
} from '@/schemas/crypto-schemas';
import type {
  CryptoKey,
  CryptoJwksKey,
  CryptoKeyStatus,
  CryptoMigration,
  CryptoMigrationAction,
  CryptoMigrationStatus,
  SigningAlgorithm,
} from '@/types/crypto';
import { formatBackendDateTime } from '@/utils/date';
import { notAvailable } from '@/utils/not-available';

type CryptoKeyResponse = {
  algorithm?: string | null;
  created_at?: string | null;
  expires_at?: string | null;
  kid: string;
  status?: string | null;
};

type CryptoKeySetResponse = {
  keys: CryptoKeyResponse[];
};

type RotateCryptoKeyResponse = {
  key_id?: string;
};

type CryptoMigrationResponse = {
  created_at?: string | null;
  source_algorithm?: string | null;
  source_key_id: string;
  status?: string | null;
  target_algorithm?: string | null;
  target_key_id?: string | null;
  updated_at?: string | null;
};

type JwkResponse = {
  alg?: string | null;
  crv?: string | null;
  kid?: string | null;
  kty?: string | null;
};

type JwksResponse = {
  keys: JwkResponse[];
};

function getTenantCryptoKeysEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/crypto/keys`;
}

function getTenantCryptoMigrationEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/crypto/migration`;
}

function getTenantJwksEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/.well-known/jwks.json`;
}

function toSigningAlgorithm(value?: string | null): SigningAlgorithm {
  if (value === 'RS256' || value === 'EdDSA') {
    return value;
  }

  return 'ES256';
}

function toCryptoKeyStatus(value?: string | null): CryptoKeyStatus {
  if (value === 'Rotated' || value === 'rotated') {
    return 'Rotated';
  }

  if (value === 'Revoked' || value === 'revoked') {
    return 'Revoked';
  }

  return 'Active';
}

function toCryptoMigrationStatus(value?: string | null): CryptoMigrationStatus {
  if (value === 'InProgress' || value === 'in_progress') {
    return 'InProgress';
  }

  if (value === 'Validating' || value === 'validating') {
    return 'Validating';
  }

  if (value === 'Completed' || value === 'completed') {
    return 'Completed';
  }

  if (value === 'RolledBack' || value === 'rolled_back') {
    return 'RolledBack';
  }

  if (value === 'Cancelled' || value === 'cancelled' || value === 'Canceled') {
    return 'Cancelled';
  }

  return 'Planned';
}

function toCryptoKey(response: CryptoKeyResponse): CryptoKey {
  return {
    algorithm: toSigningAlgorithm(response.algorithm),
    created: formatBackendDateTime(response.created_at),
    expires: formatBackendDateTime(response.expires_at),
    id: response.kid,
    status: toCryptoKeyStatus(response.status),
  };
}

function toCryptoMigration(response: CryptoMigrationResponse): CryptoMigration {
  return {
    created: formatBackendDateTime(response.created_at),
    sourceAlgorithm: toSigningAlgorithm(response.source_algorithm),
    sourceKeyId: response.source_key_id,
    status: toCryptoMigrationStatus(response.status),
    targetAlgorithm: toSigningAlgorithm(response.target_algorithm),
    targetKeyId: response.target_key_id ?? null,
    updated: formatBackendDateTime(response.updated_at),
  };
}

function toCryptoJwksKey(response: JwkResponse): CryptoJwksKey {
  return {
    algorithm: response.alg ?? notAvailable(),
    curve: response.crv ?? notAvailable(),
    id: response.kid ?? notAvailable(),
    keyType: response.kty ?? notAvailable(),
  };
}

export async function getTenantCryptoKeys(
  orgSlug: string,
  tenantSlug: string,
): Promise<CryptoKey[]> {
  const response = await apiClient.get<CryptoKeySetResponse>(
    getTenantCryptoKeysEndpoint(orgSlug, tenantSlug),
  );

  return response.data.keys.map(toCryptoKey);
}

export async function revokeTenantCryptoKey(
  orgSlug: string,
  tenantSlug: string,
  keyId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantCryptoKeysEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(keyId)}/revoke`,
  );
}

export async function rotateTenantCryptoKey(
  orgSlug: string,
  tenantSlug: string,
  payload: RotateCryptoKeyInput,
): Promise<string | undefined> {
  const response = await apiClient.post<RotateCryptoKeyResponse>(
    `${getTenantCryptoKeysEndpoint(orgSlug, tenantSlug)}/rotate`,
    payload,
  );

  return response.data.key_id;
}

export async function getTenantCryptoMigration(
  orgSlug: string,
  tenantSlug: string,
): Promise<CryptoMigration | null> {
  try {
    const response = await apiClient.get<CryptoMigrationResponse>(
      getTenantCryptoMigrationEndpoint(orgSlug, tenantSlug),
    );

    return toCryptoMigration(response.data);
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 404) {
      return null;
    }

    throw error;
  }
}

export async function executeTenantCryptoMigrationAction(
  orgSlug: string,
  tenantSlug: string,
  action: CryptoMigrationAction,
): Promise<void> {
  const actionPathByAction: Record<CryptoMigrationAction, string> = {
    Cancel: 'cancel',
    Complete: 'complete',
    Promote: 'promote',
    Rollback: 'rollback',
    Start: 'start',
  };

  await apiClient.post(
    `${getTenantCryptoMigrationEndpoint(orgSlug, tenantSlug)}/${actionPathByAction[action]}`,
  );
}

export async function planTenantCryptoMigration(
  orgSlug: string,
  tenantSlug: string,
  payload: PlanCryptoMigrationInput,
): Promise<void> {
  await apiClient.post(`${getTenantCryptoMigrationEndpoint(orgSlug, tenantSlug)}/plan`, {
    target_algorithm: payload.targetAlgorithm,
  });
}

export async function rollbackTenantCryptoMigration(
  orgSlug: string,
  tenantSlug: string,
  payload: RollbackCryptoMigrationInput,
): Promise<void> {
  await apiClient.post(`${getTenantCryptoMigrationEndpoint(orgSlug, tenantSlug)}/rollback`, {
    reason: payload.reason,
  });
}

export async function getTenantJwksKeys(
  orgSlug: string,
  tenantSlug: string,
): Promise<CryptoJwksKey[]> {
  try {
    const response = await apiClient.get<JwksResponse>(getTenantJwksEndpoint(orgSlug, tenantSlug));

    return response.data.keys.map(toCryptoJwksKey);
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 404) {
      return [];
    }

    throw error;
  }
}
