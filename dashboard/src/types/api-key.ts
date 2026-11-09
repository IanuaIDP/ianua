export type ApiKeyStatus = 'Active' | 'Revoked' | 'Expired';

export type ApiKeySortField = 'created_at' | 'last_used_at' | 'name';
export type ApiKeySortDirection = 'asc' | 'desc';
export type ApiKeyAction = 'Revoke';

export type ApiKey = {
  created: string;
  createdBy: string | null;
  expires: string | null;
  id: string;
  key: string;
  lastUsed: string;
  name: string;
  status: ApiKeyStatus;
};

export type CreatedApiKey = {
  id?: string;
  key: string;
  keyPrefix?: string;
};

export type ApiKeyList = {
  items: ApiKey[];
  limit: number;
  nextCursor: string | null;
};
