export type RoleAction = 'Edit' | 'Delete';

export type RoleSortField = 'created_at' | 'updated_at' | 'name';

export type RoleSortDirection = 'asc' | 'desc';

export type RolePermission = {
  action: string;
  resource: string;
};

export type Role = {
  assignedUserCount: number;
  createdAt: string;
  customPermissions: RolePermission[];
  id: string;
  isDefault: boolean;
  name: string;
  permissionsCount: number;
  systemPermissions: Record<string, string>[];
};

export type RoleList = {
  items: Role[];
  limit: number;
  nextCursor: string | null;
};
