export type TenantApiKeyStatus = 'Active' | 'Paused' | 'Revoked' | 'Expired';

export type TenantApiKeyAction = 'Pause' | 'Resume' | 'Revoke';

export type TenantApiKeySortField = 'created_at' | 'name' | 'expires_at' | 'last_used_at';

export type TenantApiKeySortDirection = 'asc' | 'desc';

export type TenantApiKey = {
  created: string;
  ends: string | null;
  id: string;
  lastUsed: string;
  lastUsedIp: string | null;
  name: string;
  scopes: string[];
  status: TenantApiKeyStatus;
};

export type CreatedTenantApiKey = {
  id?: string;
  key: string;
};

export type TenantApiKeyList = {
  items: TenantApiKey[];
  limit: number;
  nextCursor: string | null;
};
