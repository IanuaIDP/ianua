import { apiClient } from '@/lib/api/client';
import { buildSortParam, createResource, getList } from '@/lib/api/crud';
import type { AddDomainInput } from '@/schemas/domain-schemas';
import type {
  Domain,
  DomainCertificate,
  DomainConnection,
  DomainList,
  DomainSortDirection,
  DomainSortField,
  DomainTlsStatus,
  DomainVerificationStatus,
  TrafficRecord,
  TrafficRecords,
} from '@/types/domain';
import { formatBackendDate, formatBackendDateTime } from '@/utils/date';

type TrafficRecordResponse = {
  name?: string | null;
  record_type?: string | null;
  value?: string | null;
};

type TrafficRecordsResponse = {
  bare_domain?: TrafficRecordResponse | null;
  delegation?: TrafficRecordResponse[] | null;
  subdomain?: TrafficRecordResponse | null;
};

type DomainResponse = {
  caa_record?: string | null;
  connection?: string | null;
  created_at?: string | null;
  dns_record_name?: string | null;
  dns_record_value?: string | null;
  domain?: string | null;
  id: string;
  is_auto_verified?: boolean | null;
  tls_status?: string | null;
  traffic_records?: TrafficRecordsResponse | null;
  verification_status?: string | null;
  verified_at?: string | null;
};

type DomainCertificateResponse = {
  days_until_expiry: number;
  expires_at: string;
  issued_at: string;
  issuer?: string | null;
  renewal: string;
  source: string;
};

type DomainDetailResponse = DomainResponse & {
  certificate?: DomainCertificateResponse | null;
};

type DomainListResponse = {
  items: DomainResponse[];
  limit: number;
  next_cursor: string | null;
};

type GetTenantDomainsParams = {
  after?: string;
  limit?: number;
  sortDirection?: DomainSortDirection;
  sortField?: DomainSortField;
};

type CreateDomainRequest = {
  connection: DomainConnection;
  domain: string;
};

function toDomainVerificationStatus(value?: string | null): DomainVerificationStatus {
  const normalizedValue = value?.toLowerCase();

  if (normalizedValue === 'verified') {
    return 'Verified';
  }

  if (normalizedValue === 'failed') {
    return 'Failed';
  }

  return 'Pending';
}

/**
 * The API's four `tls_status` values, unchanged.
 *
 * The version this replaced matched only the literal `"enabled"`, which the
 * API has never sent — so every domain read as `Disabled`, including ones
 * serving a valid certificate.
 */
function toDomainTlsStatus(value?: string | null): DomainTlsStatus {
  switch (value?.toLowerCase()) {
    case 'active':
      return 'Active';
    case 'provisioning':
      return 'Provisioning';
    case 'expired':
      return 'Expired';
    default:
      return 'NotRequired';
  }
}

function toDomainConnection(value?: string | null): DomainConnection {
  return value?.toLowerCase() === 'delegated' ? 'Delegated' : 'SelfManaged';
}

function toTrafficRecord(response?: TrafficRecordResponse | null): TrafficRecord | undefined {
  if (!response?.value) {
    return undefined;
  }

  return {
    name: response.name ?? '',
    recordType: response.record_type ?? '',
    value: response.value,
  };
}

function toTrafficRecords(response?: TrafficRecordsResponse | null): TrafficRecords {
  return {
    bareDomain: toTrafficRecord(response?.bare_domain),
    delegation: (response?.delegation ?? [])
      .map(toTrafficRecord)
      .filter((record): record is TrafficRecord => Boolean(record)),
    subdomain: toTrafficRecord(response?.subdomain),
  };
}

function toDomain(response: DomainResponse): Domain {
  return {
    caaRecord: response.caa_record ?? '',
    connection: toDomainConnection(response.connection),
    created: formatBackendDate(response.created_at),
    dnsRecordName: response.dns_record_name ?? '',
    dnsRecordValue: response.dns_record_value ?? '',
    domain: response.domain ?? '',
    id: response.id,
    isAutoVerified: Boolean(response.is_auto_verified),
    tlsStatus: toDomainTlsStatus(response.tls_status),
    trafficRecords: toTrafficRecords(response.traffic_records),
    verificationStatus: toDomainVerificationStatus(response.verification_status),
    verifiedAt: formatBackendDate(response.verified_at),
  };
}

export function getTenantDomainsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(tenantSlug)}/domains`;
}

function toDomainCertificate(
  response?: DomainCertificateResponse | null,
): DomainCertificate | null {
  if (!response) {
    return null;
  }

  return {
    daysUntilExpiry: response.days_until_expiry,
    expiresAt: formatBackendDateTime(response.expires_at),
    issuedAt: formatBackendDateTime(response.issued_at),
    issuer: response.issuer ?? null,
    renewal: response.renewal,
    source: response.source,
  };
}

export async function getTenantDomain(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
): Promise<Domain | undefined> {
  const response = await getList<DomainDetailResponse>(
    `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}`,
  );

  return { ...toDomain(response), certificate: toDomainCertificate(response.certificate) };
}

export async function getTenantDomains(
  orgSlug: string,
  tenantSlug: string,
  params?: GetTenantDomainsParams,
): Promise<DomainList> {
  const sort = buildSortParam(params?.sortField, params?.sortDirection);

  const response = await getList<DomainListResponse>(
    getTenantDomainsEndpoint(orgSlug, tenantSlug),
    {
      params: {
        after: params?.after,
        limit: params?.limit,
        sort,
      },
    },
  );

  return {
    items: response.items.map(toDomain),
    limit: response.limit,
    nextCursor: response.next_cursor,
  };
}

export async function deleteTenantDomain(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
): Promise<void> {
  await apiClient.delete(
    `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}`,
  );
}

export async function createTenantDomain(
  orgSlug: string,
  tenantSlug: string,
  payload: AddDomainInput,
): Promise<Domain> {
  const response = await createResource<DomainResponse, CreateDomainRequest>(
    getTenantDomainsEndpoint(orgSlug, tenantSlug),
    {
      connection: payload.connection,
      domain: payload.domain,
    },
  );

  return toDomain(response);
}

/**
 * Kicks off a DNS check for a domain still in `Pending`.
 *
 * Verification only ever promotes: a check that finds nothing yet returns
 * `Pending` again, never `Failed`. Callers should treat that as "not yet",
 * not as an error, and rely on the domain list refetch to reflect the result.
 */
export async function verifyTenantDomain(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
): Promise<DomainVerificationStatus> {
  const response = await apiClient.post<{ status?: string | null }>(
    `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}/verify`,
  );

  return toDomainVerificationStatus(response.data?.status);
}

/**
 * Asks for a certificate for a verified domain whose TLS is stuck at
 * `NotRequired` or `Expired` — certificates are otherwise requested
 * automatically on verification. The API queues it and answers at once; the
 * domain reads `Provisioning` until the certificate is issued.
 */
export async function provisionTenantDomainTls(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}/provision-tls`,
  );
}

type TransferDomainRequest = {
  target_tenant_id: string;
};

/**
 * Moves a domain to another tenant in the same organization, preserving its
 * verification and TLS state. Fails 409 if the target is the same tenant or
 * belongs to a different organization.
 */
export async function transferTenantDomain(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
  targetTenantId: string,
): Promise<void> {
  await apiClient.post(
    `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}/handover`,
    { target_tenant_id: targetTenantId } satisfies TransferDomainRequest,
  );
}
