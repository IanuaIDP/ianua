import type {
  CaaRecordTag,
  CaaRecordValue,
  DnsRecord,
  DnsRecordType,
  MxRecordValue,
  SrvRecordValue,
} from '@/types/dns-record';

export function isSingleValueRecordType(recordType: DnsRecordType) {
  return recordType === 'CNAME';
}

export function isStructuredRecordType(recordType: DnsRecordType) {
  return recordType === 'MX' || recordType === 'SRV' || recordType === 'CAA';
}

export function isMultilineRecordType(recordType: DnsRecordType) {
  return recordType === 'TXT';
}

export function emptyMxValue(): MxRecordValue {
  return { host: '', priority: '10' };
}

export function emptySrvValue(): SrvRecordValue {
  return { host: '', port: '', priority: '10', weight: '5' };
}

export function emptyCaaValue(): CaaRecordValue {
  return { isCritical: false, tag: 'issue', value: '' };
}

export function assembleMxValue(value: MxRecordValue) {
  return `${value.priority.trim()} ${value.host.trim()}`.trim();
}

export function parseMxValue(raw: string): MxRecordValue {
  const [priority = '', ...rest] = raw.trim().split(/\s+/);

  return { host: rest.join(' '), priority };
}

export function assembleSrvValue(value: SrvRecordValue) {
  return `${value.priority.trim()} ${value.weight.trim()} ${value.port.trim()} ${value.host.trim()}`.trim();
}

export function parseSrvValue(raw: string): SrvRecordValue {
  const [priority = '', weight = '', port = '', ...rest] = raw.trim().split(/\s+/);

  return { host: rest.join(' '), port, priority, weight };
}

export function assembleCaaValue(value: CaaRecordValue) {
  const flags = value.isCritical ? '128' : '0';
  const unquoted = value.value.trim().replace(/^"|"$/g, '');

  return `${flags} ${value.tag} "${unquoted}"`;
}

const caaPattern = /^(\d+)\s+(\S+)\s+"?([^"]*)"?$/;

export function parseCaaValue(raw: string): CaaRecordValue {
  const match = raw.trim().match(caaPattern);

  if (!match) {
    return emptyCaaValue();
  }

  const [, flags, tag, value] = match;

  return {
    isCritical: flags === '128',
    tag: (['issue', 'issuewild', 'iodef'] as CaaRecordTag[]).includes(tag as CaaRecordTag)
      ? (tag as CaaRecordTag)
      : 'issue',
    value,
  };
}

export function toMultiValues(record?: DnsRecord | null): string[] {
  if (!record || record.values.length === 0) {
    return [''];
  }

  return record.values;
}

export function toMxValues(record?: DnsRecord | null): MxRecordValue[] {
  if (!record || record.values.length === 0) {
    return [emptyMxValue()];
  }

  return record.values.map(parseMxValue);
}

export function toSrvValues(record?: DnsRecord | null): SrvRecordValue[] {
  if (!record || record.values.length === 0) {
    return [emptySrvValue()];
  }

  return record.values.map(parseSrvValue);
}

export function toCaaValues(record?: DnsRecord | null): CaaRecordValue[] {
  if (!record || record.values.length === 0) {
    return [emptyCaaValue()];
  }

  return record.values.map(parseCaaValue);
}

export function formatDnsRecordValueForDisplay(recordType: DnsRecordType, value: string) {
  if (recordType === 'MX') {
    const parsed = parseMxValue(value);

    return `${parsed.host} (priority ${parsed.priority})`;
  }

  if (recordType === 'SRV') {
    const parsed = parseSrvValue(value);

    return `${parsed.host}:${parsed.port} (priority ${parsed.priority}, weight ${parsed.weight})`;
  }

  return value;
}
