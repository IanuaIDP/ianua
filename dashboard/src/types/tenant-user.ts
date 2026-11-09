import type { UserAttributeValues } from '@/types/user-attribute';

export type TenantUserStatus =
  | 'Invited'
  | 'PendingVerification'
  | 'Active'
  | 'Locked'
  | 'InvitationExpired'
  | 'Deactivated'
  | 'Closing';

export type TenantUserTab = 'All' | TenantUserStatus;

export type TenantUserAction =
  | 'Edit user fields'
  | 'Lock'
  | 'Delete Forever'
  | 'Restore Access'
  | 'Reset Password'
  | 'Revoke Invitation'
  | 'Resend Invitation';

export type TenantUserSortField =
  'created_at' | 'updated_at' | 'email' | 'display_name' | 'status' | 'last_login_at';

export type TenantUserSortDirection = 'asc' | 'desc';

export type TenantUserRole = {
  id: string;
  name: string;
};

export type TenantUserProfile = {
  department: string | null;
  employeeNumber: string | null;
  externalId: string | null;
  familyName: string | null;
  givenName: string | null;
  managerId: string | null;
  phoneNumber: string | null;
  picture: string | null;
  preferredUsername: string | null;
};

export type TenantUser = {
  /** The tenant's own custom fields, keyed by `<namespace>.<key>`. */
  attributes: UserAttributeValues;
  avatarInitial: string;
  created: string;
  displayName: string;
  email: string;
  emailVerified: boolean;
  id: string;
  /** The role accepting the invitation grants; `null` once they have joined. */
  invitedRole: TenantUserRole | null;
  /** When they accepted; `null` until then. */
  joined: string | null;
  lastLogin: string;
  profile: TenantUserProfile;
  roles: TenantUserRole[];
  status: TenantUserStatus;
  updated: string;
};

export type TenantUserList = {
  items: TenantUser[];
  limit: number;
  nextCursor: string | null;
};
