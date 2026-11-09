import type { DnsRecordType } from '@/types/dns-record';

export const DNS_RECORD_TYPES: DnsRecordType[] = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'];

export const CAA_TAGS = ['issue', 'issuewild', 'iodef'] as const;

export const DNS_RECORD_TTL_MIN_SECONDS = 60;
export const DNS_RECORD_TTL_MAX_SECONDS = 3600;
export const DNS_RECORD_DEFAULT_TTL_SECONDS = 300;

export const DNS_RECORD_VALUE_PLACEHOLDERS: Partial<Record<DnsRecordType, string>> = {
  A: '203.0.113.10',
  AAAA: '2001:db8::1',
  TXT: 'v=spf1 include:_spf.google.com ~all',
};
