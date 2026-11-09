import type { LooseTranslator } from '@/hooks/i18n/use-loose-translations';
import type {
  DnsInstructions,
  Domain,
  DomainInstructionField,
  TrafficRecord,
} from '@/types/domain';

function recordRows(
  heading: string,
  record: TrafficRecord,
  t: LooseTranslator,
): DomainInstructionField[] {
  return [
    { isCopyable: false, label: t('row.type', { heading }), value: record.recordType },
    { label: t('row.name', { heading }), tooltipSide: 'left', value: record.name },
    { label: t('row.to', { heading }), tooltipSide: 'left', value: record.value },
  ];
}

function selfManagedInstructions(domain: Domain, t: LooseTranslator): DnsInstructions {
  const { bareDomain, subdomain } = domain.trafficRecords;

  return {
    description: t('selfManaged.description'),
    fields: [
      { isCopyable: false, label: t('selfManaged.verifyType'), value: 'TXT' },
      { label: t('selfManaged.verifyName'), tooltipSide: 'left', value: domain.dnsRecordName },
      { label: t('selfManaged.verifyTo'), tooltipSide: 'left', value: domain.dnsRecordValue },
      ...(subdomain ? recordRows(t('selfManaged.subdomain'), subdomain, t) : []),
      ...(bareDomain ? recordRows(t('selfManaged.bareDomain'), bareDomain, t) : []),
      ...(domain.caaRecord
        ? [{ label: t('selfManaged.caa'), tooltipSide: 'left' as const, value: domain.caaRecord }]
        : []),
    ],
    notes: [t('selfManaged.note')],
  };
}

function delegatedInstructions(domain: Domain, t: LooseTranslator): DnsInstructions {
  const nameservers = domain.trafficRecords.delegation;

  if (nameservers.length === 0) {
    return {
      description: t('delegated.unavailable'),
      fields: [],
      notes: [t('delegated.unavailableNote')],
    };
  }

  const hostname = nameservers[0]?.name ?? domain.domain;
  const hostLabel = hostname.split('.')[0];

  return {
    description: t('delegated.description'),
    fields: [
      { isCopyable: false, label: t('delegated.type'), value: 'NS' },
      { label: t('delegated.name'), tooltipSide: 'left', value: hostname },
      ...nameservers.map((record, index) => ({
        label: t('delegated.nameserver', { n: index + 1 }),
        tooltipSide: 'left' as const,
        value: record.value,
      })),
    ],
    notes: [
      t('delegated.note1', { hostLabel, hostname }),
      t('delegated.note2'),
      t('delegated.note3'),
      t('delegated.note4'),
    ],
  };
}

/** `t` is the translator of `dashboard.domains.instructions`. */
export function getDnsInstructions(domain: Domain, t: LooseTranslator): DnsInstructions {
  return domain.connection === 'Delegated'
    ? delegatedInstructions(domain, t)
    : selfManagedInstructions(domain, t);
}

/** How often a domain waiting on its certificate is fetched again. */
export const CERTIFICATE_POLL_INTERVAL_MS = 5000;

/**
 * Whether a verified domain's certificate is still being issued. Issuing runs
 * in the background, so a view showing one fetches it again until it is done.
 * An unverified domain also reads `Provisioning`, but nothing is being issued
 * for it yet.
 */
export function isAwaitingCertificate(domain: Domain | undefined): boolean {
  return domain?.verificationStatus === 'Verified' && domain.tlsStatus === 'Provisioning';
}
