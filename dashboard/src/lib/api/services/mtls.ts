import { apiClient } from '@/lib/api/client';
import { toFreshProofBody, type FreshProofBody } from '@/lib/api/reentered-proof';
import type { MtlsConfigInput } from '@/schemas/mtls-schemas';
import type { ReenteredProof } from '@/types/auth';
import type { MtlsConfig, MtlsMode } from '@/types/mtls';

type MtlsConfigResponse = {
  mode?: MtlsMode | null;
  trusted_ca_certs?: string[] | null;
};

type UpdateMtlsConfigRequest = {
  mode: MtlsMode;
  proof: FreshProofBody;
  trusted_ca_certs: string[];
};

function getMtlsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/mtls`;
}

function splitPemCertificates(text: string): string[] {
  const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);

  return matches ? matches.map((cert) => cert.trim()) : [];
}

function toMtlsConfig(response: MtlsConfigResponse): MtlsConfig {
  return {
    mode: response.mode ?? 'Disabled',
    trustedCaCerts: response.trusted_ca_certs ?? [],
  };
}

export async function getTenantMtlsConfig(
  orgSlug: string,
  tenantSlug: string,
): Promise<MtlsConfig> {
  const response = await apiClient.get<MtlsConfigResponse>(getMtlsEndpoint(orgSlug, tenantSlug));

  return toMtlsConfig(response.data);
}

export async function updateTenantMtlsConfig(
  orgSlug: string,
  tenantSlug: string,
  payload: MtlsConfigInput,
  proof: ReenteredProof,
): Promise<MtlsConfig> {
  const requestBody: UpdateMtlsConfigRequest = {
    mode: payload.mode,
    proof: toFreshProofBody(proof),
    trusted_ca_certs: splitPemCertificates(payload.trustedCaCertsText),
  };

  await apiClient.patch<unknown>(getMtlsEndpoint(orgSlug, tenantSlug), requestBody);

  return getTenantMtlsConfig(orgSlug, tenantSlug);
}
