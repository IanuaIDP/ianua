export type GroupAction = 'Edit' | 'Members' | 'Roles' | 'Delete';

export type GroupSortField = 'created_at' | 'updated_at' | 'name';

export type GroupSortDirection = 'asc' | 'desc';

export type GroupMemberKind = 'user' | 'org_user' | 'agent' | 'consumer';

export type GroupMember = {
  displayName: string;
  id: string;
  joinedAt: string;
  kind: GroupMemberKind;
};

export type Group = {
  createdAt: string;
  id: string;
  name: string;
  parentId?: string;
  roleIds: string[];
  rolesCount: number;
  updatedAt: string;
};

export type GroupList = {
  items: Group[];
  limit: number;
  nextCursor: string | null;
};
