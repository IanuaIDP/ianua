import { apiClient } from '@/lib/api/client';
import { getTenantDomainsEndpoint } from '@/lib/api/services/domains';
import type {
  DnsRecord,
  DnsRecordSetInput,
  DnsRecordSetKey,
  DnsRecordType,
} from '@/types/dns-record';

type DnsRecordResponse = {
  is_managed_by_ianua?: boolean | null;
  name?: string | null;
  record_type?: string | null;
  ttl_seconds?: number | null;
  values?: string[] | null;
};

type DnsRecordSetRequest = {
  name: string;
  record_type: DnsRecordType;
  ttl_seconds?: number;
  values: string[];
};

type DnsRecordSetKeyRequest = {
  name: string;
  record_type: DnsRecordType;
};

const knownRecordTypes: DnsRecordType[] = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'SRV', 'TXT'];

function toDnsRecordType(value?: string | null): DnsRecordType {
  const normalized = value?.toUpperCase();

  return (knownRecordTypes as string[]).includes(normalized ?? '')
    ? (normalized as DnsRecordType)
    : 'TXT';
}

function toDnsRecord(response: DnsRecordResponse): DnsRecord {
  return {
    isManagedByIanua: Boolean(response.is_managed_by_ianua),
    name: response.name ?? '',
    recordType: toDnsRecordType(response.record_type),
    ttlSeconds: response.ttl_seconds ?? 300,
    values: response.values ?? [],
  };
}

function getTenantDomainDnsEndpoint(orgSlug: string, tenantSlug: string, domainId: string) {
  return `${getTenantDomainsEndpoint(orgSlug, tenantSlug)}/${encodeURIComponent(domainId)}/dns`;
}

export async function getTenantDomainDnsRecords(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
): Promise<DnsRecord[]> {
  const response = await apiClient.get<DnsRecordResponse[]>(
    getTenantDomainDnsEndpoint(orgSlug, tenantSlug, domainId),
  );

  return (response.data ?? []).map(toDnsRecord);
}

export async function putTenantDomainDnsRecord(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
  payload: DnsRecordSetInput,
): Promise<void> {
  await apiClient.put(getTenantDomainDnsEndpoint(orgSlug, tenantSlug, domainId), {
    name: payload.name,
    record_type: payload.recordType,
    ttl_seconds: payload.ttlSeconds,
    values: payload.values,
  } satisfies DnsRecordSetRequest);
}

export async function deleteTenantDomainDnsRecord(
  orgSlug: string,
  tenantSlug: string,
  domainId: string,
  payload: DnsRecordSetKey,
): Promise<void> {
  await apiClient.delete(getTenantDomainDnsEndpoint(orgSlug, tenantSlug, domainId), {
    data: {
      name: payload.name,
      record_type: payload.recordType,
    } satisfies DnsRecordSetKeyRequest,
  });
}
