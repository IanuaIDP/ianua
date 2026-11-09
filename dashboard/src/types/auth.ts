export type SocialButtonProvider = 'google' | 'github' | 'passkey';

export type User = {
  id: string;
  email: string;
  name: string;
  organizationId?: string;
  organizationName?: string;
  organizationSlug?: string;
  tenantId?: string;
  tenantName?: string;
  tenantSlug?: string;
};

export type LoginRequest = {
  email: string;
  fingerprint_hash?: string;
  organization?: string;
  password: string;
  tenant_slug?: string;
};

/** The password typed again for a change the API wants proven afresh. */
export type ReenteredProof = {
  /** A code from the person's second factor, when the API asks for it. */
  code?: string;
  password: string;
};

/** What the breach lookup said about a password just set. */
export type PasswordBreach = {
  isBreached: boolean;
  occurrences: number | null;
};

export type OrgRole = 'Owner' | 'Admin' | 'Member' | 'Billing' | 'Viewer';

export type AccessTenant = {
  displayName: string;
  permissions: string[];
  roles: string[];
  slug: string;
  tenantId: string;
};

export type Access = {
  role: OrgRole;
  tenants: AccessTenant[];
};

export type LoginResponse = {
  access: Access | null;
  accessToken: string;
  user: User;
};

export type AuthState = {
  access: Access | null;
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isHydrated: boolean;
};
