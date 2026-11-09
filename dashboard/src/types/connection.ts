export type ConnectionStatus = 'Active' | 'Disabled';

export type ConnectionAction = 'Activate' | 'Disable' | 'Delete';

export type ConnectionSortField = 'created_at' | 'provider_name' | 'status';

export type ConnectionSortDirection = 'asc' | 'desc';

export type Connection = {
  allowedDomains: string[];
  assuranceTrust: 'Untrusted' | 'Trusted' | null;
  attributeMapping: Record<string, string>;
  created: string;
  domainHint: string | null;
  emailTrust: 'Unverified' | 'Authoritative' | null;
  groupMapping: Record<string, unknown> | null;
  id: string;
  isJitProvisioningEnabled: boolean;
  saml: Record<string, unknown> | null;
  name: string;
  protocol: string;
  status: ConnectionStatus;
};

export type ConnectionList = {
  items: Connection[];
  limit: number;
  nextCursor: string | null;
};
