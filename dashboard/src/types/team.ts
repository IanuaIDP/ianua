import type { OrgRole } from '@/types/auth';

export type TeamMemberStatus =
  'Active' | 'Locked' | 'Invited' | 'PendingVerification' | 'InvitationExpired';

export type TeamMemberTab = 'All' | TeamMemberStatus;

export type TeamMemberSortField = 'created_at' | 'display_name';

export type TeamMemberSortDirection = 'asc' | 'desc';

export type TeamMemberAction =
  | 'Lock'
  | 'Delete Forever'
  | 'Restore Access'
  | 'Reset Password'
  | 'Reset Second Factor'
  | 'Tenant Access'
  | 'Revoke Invitation'
  | 'Resend Invitation';

export type TeamMember = {
  id: number | string;
  email: string;
  created: string;
  joined: string;
  name: string;
  role: OrgRole;
  status: TeamMemberStatus;
  avatarInitial: string;
};

export type TeamMemberList = {
  items: TeamMember[];
  limit: number;
  nextCursor: string | null;
};
