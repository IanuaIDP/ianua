export type DnsRecordType = 'A' | 'AAAA' | 'CAA' | 'CNAME' | 'MX' | 'SRV' | 'TXT';

export type DnsRecord = {
  isManagedByIanua: boolean;
  name: string;
  recordType: DnsRecordType;
  ttlSeconds: number;
  values: string[];
};

export type DnsRecordSetKey = {
  name: string;
  recordType: DnsRecordType;
};

export type DnsRecordSetInput = DnsRecordSetKey & {
  ttlSeconds?: number;
  values: string[];
};

export type MxRecordValue = {
  host: string;
  priority: string;
};

export type SrvRecordValue = {
  host: string;
  port: string;
  priority: string;
  weight: string;
};

export type CaaRecordTag = 'iodef' | 'issue' | 'issuewild';

export type CaaRecordValue = {
  isCritical: boolean;
  tag: CaaRecordTag;
  value: string;
};
