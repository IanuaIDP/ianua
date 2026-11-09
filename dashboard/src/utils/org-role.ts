import type { OrgRole } from '@/types/auth';

export const ORG_ROLES: OrgRole[] = ['Owner', 'Admin', 'Member', 'Billing', 'Viewer'];

/** What an organization role lets its holder do, as the platform decides it. */
export type OrgRights = {
  canCloseOrganization: boolean;
  canManageBilling: boolean;
  canManageOrganization: boolean;
  canReachTenants: boolean;
  canViewAuditLog: boolean;
  canViewBilling: boolean;
  canViewMembers: boolean;
  canViewTenants: boolean;
};

const roleRights: Record<OrgRole, OrgRights> = {
  Admin: {
    canCloseOrganization: false,
    canManageBilling: false,
    canManageOrganization: true,
    canReachTenants: true,
    canViewAuditLog: true,
    canViewBilling: true,
    canViewMembers: true,
    canViewTenants: true,
  },
  Billing: {
    canCloseOrganization: false,
    canManageBilling: true,
    canManageOrganization: false,
    canReachTenants: false,
    canViewAuditLog: false,
    canViewBilling: true,
    canViewMembers: false,
    canViewTenants: false,
  },
  Member: {
    canCloseOrganization: false,
    canManageBilling: false,
    canManageOrganization: false,
    canReachTenants: true,
    canViewAuditLog: true,
    canViewBilling: false,
    canViewMembers: true,
    canViewTenants: true,
  },
  Owner: {
    canCloseOrganization: true,
    canManageBilling: true,
    canManageOrganization: true,
    canReachTenants: true,
    canViewAuditLog: true,
    canViewBilling: true,
    canViewMembers: true,
    canViewTenants: true,
  },
  Viewer: {
    canCloseOrganization: false,
    canManageBilling: false,
    canManageOrganization: false,
    canReachTenants: false,
    canViewAuditLog: true,
    canViewBilling: true,
    canViewMembers: true,
    canViewTenants: true,
  },
};

const noRights: OrgRights = {
  canCloseOrganization: false,
  canManageBilling: false,
  canManageOrganization: false,
  canReachTenants: false,
  canViewAuditLog: false,
  canViewBilling: false,
  canViewMembers: false,
  canViewTenants: false,
};

export function getOrgRights(role: OrgRole | null | undefined): OrgRights {
  return role ? roleRights[role] : noRights;
}

/** Whether tenant access comes one grant at a time, or not at all, for this role. */
export function isTenantAccessGated(role: OrgRole | null | undefined) {
  return role === 'Member' || role === 'Billing' || role === 'Viewer';
}

/**
 * The roles this holder may give, take away, or act on. Only an owner makes
 * an owner or a billing contact; an admin makes admins, members and viewers.
 */
export function getAssignableOrgRoles(role: OrgRole | null | undefined): OrgRole[] {
  if (role === 'Owner') {
    return ORG_ROLES;
  }

  if (role === 'Admin') {
    return ['Admin', 'Member', 'Viewer'];
  }

  return [];
}
