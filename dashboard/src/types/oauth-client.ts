export type OAuthClientStatus = 'Active' | 'Revoked';

export type OAuthClientAction = 'Revoke' | 'Edit' | 'Rotate secret';

export type OAuthClientSortField = 'created_at' | 'name' | 'status';

export type OAuthClientSortDirection = 'asc' | 'desc';

export type OAuthClient = {
  clientId: string;
  created: string;
  grantTypes: string[];
  id: string;
  name: string;
  redirectUris: string[];
  scopes: string[];
  settings: Record<string, unknown>;
  status: OAuthClientStatus;
};

export type OAuthClientList = {
  items: OAuthClient[];
  limit: number;
  nextCursor: string | null;
};

export type CreatedOAuthClient = {
  clientId: string;
  clientSecret: string;
};
