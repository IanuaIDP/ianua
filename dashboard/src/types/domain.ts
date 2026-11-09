export type DomainAction = 'Delete' | 'ProvisionTls' | 'Transfer' | 'Verify' | 'ViewInstructions';

/** Who runs the DNS for a domain: the tenant, or us. */
export type DomainConnection = 'SelfManaged' | 'Delegated';

export type DomainVerificationStatus = 'Verified' | 'Pending' | 'Failed';

/**
 * Where a domain's certificate stands. Mirrors the API's `tls_status`.
 *
 * `Provisioning` is not a failure — it is the ordinary state between a domain
 * being verified and the certificate authority issuing for it.
 */
export type DomainTlsStatus = 'NotRequired' | 'Provisioning' | 'Active' | 'Expired';

export type DomainSortField = 'created_at' | 'domain' | 'verification_status' | 'verified_at';

export type DomainSortDirection = 'asc' | 'desc';

/** One DNS record, as a tenant would type it into their provider. */
export type TrafficRecord = {
  name: string;
  recordType: string;
  value: string;
};

/**
 * The records that bring traffic here. Exactly one group applies.
 *
 * A `SelfManaged` domain gets `subdomain`, and `bareDomain` too when the name
 * is a zone apex, which may not hold a CNAME. A `Delegated` domain gets
 * `delegation` instead: once those NS records resolve the zone is ours, and
 * writing them is what proves the handover — so a delegated domain needs no
 * TXT token at all.
 */
export type TrafficRecords = {
  bareDomain?: TrafficRecord;
  delegation: TrafficRecord[];
  subdomain?: TrafficRecord;
};

export type DomainCertificate = {
  daysUntilExpiry: number;
  expiresAt: string;
  issuedAt: string;
  issuer: string | null;
  renewal: string;
  source: string;
};

export type Domain = {
  caaRecord: string;
  /** Only the single-domain read carries it. */
  certificate?: DomainCertificate | null;
  connection: DomainConnection;
  created: string;
  dnsRecordName: string;
  dnsRecordValue: string;
  domain: string;
  id: string;
  isAutoVerified: boolean;
  tlsStatus: DomainTlsStatus;
  trafficRecords: TrafficRecords;
  verificationStatus: DomainVerificationStatus;
  verifiedAt: string;
};

export type DomainList = {
  items: Domain[];
  limit: number;
  nextCursor: string | null;
};

export type DomainInstructionField = {
  isCopyable?: boolean;
  label: string;
  tooltipSide?: 'left';
  value: string;
};

export type DnsInstructions = {
  description: string;
  fields: DomainInstructionField[];
  notes: string[];
};
