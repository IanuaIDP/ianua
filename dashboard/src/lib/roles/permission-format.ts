import type { Role, RolePermission } from '@/types/role';
import type { Permission, PermissionValue } from '@/types/permission';

export type RolePermissionSummaryGroup = {
  actions: string[];
  label: string;
  resource: string;
};

const PERMISSION_LABEL_ACRONYMS = new Set(['api', 'scim']);

function formatWord(word: string) {
  return PERMISSION_LABEL_ACRONYMS.has(word.toLowerCase())
    ? word.toUpperCase()
    : `${word.charAt(0).toUpperCase()}${word.slice(1)}`;
}

function formatActionLabel(action: string) {
  return action === 'Manage' ? 'Full Access' : action;
}

export function formatGroupLabel(label: string) {
  return label.split('_').map(formatWord).join(' ');
}

export function formatResourceLabel(resource: string) {
  const words = resource.match(/[A-Z][a-z0-9]*/g) ?? [resource];

  return words.map(formatWord).join(' ');
}

export function formatPermissionLabel(permission: Permission) {
  const action = Object.values(permission.value)[0] ?? permission.label;

  return formatActionLabel(action);
}

export function permissionValueKey(value: PermissionValue) {
  return JSON.stringify(value);
}

export function summarizeRolePermissions(
  role: Pick<Role, 'customPermissions' | 'systemPermissions'>,
): RolePermissionSummaryGroup[] {
  const actionsByResource = new Map<string, string[]>();

  function addAction(resource: string, action: string) {
    const displayAction = formatActionLabel(action);
    const existingActions = actionsByResource.get(resource);

    if (!existingActions) {
      actionsByResource.set(resource, [displayAction]);
      return;
    }

    if (!existingActions.includes(displayAction)) {
      existingActions.push(displayAction);
    }
  }

  function addSystemPermission(permission: Record<string, string>) {
    for (const [resource, action] of Object.entries(permission)) {
      addAction(resource, action);
    }
  }

  function addCustomPermission(permission: RolePermission) {
    addAction(permission.resource, permission.action);
  }

  role.customPermissions.forEach(addCustomPermission);
  role.systemPermissions.forEach(addSystemPermission);

  return Array.from(actionsByResource.entries()).map(([resource, actions]) => ({
    actions,
    label: formatResourceLabel(resource),
    resource,
  }));
}
