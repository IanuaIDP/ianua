import type { Permission, PermissionGroup, PermissionValue } from '@/types/permission';
import type { ResourceType } from '@/types/resource-type';

/**
 * The tenant's declared permissions, shaped for the same picker system
 * permissions use.
 *
 * One picker rather than two lists is the point: an operator granting access
 * should not have to know which side of the platform boundary a permission
 * falls on, and a permission that can only be typed is one that can be
 * mistyped.
 */
export function toCataloguePermissionGroups(resourceTypes: ResourceType[]): PermissionGroup[] {
  return resourceTypes.map((resourceType) => ({
    label: resourceType.displayName,
    permissions: resourceType.actions.map((action) => ({
      label: action.displayName,
      value: { [resourceType.key]: action.key },
    })),
  }));
}

/**
 * Every `resource:action` pair the catalogue declares, as picker keys.
 *
 * Used to tell a custom permission from a system one on submit. Membership
 * rather than a naming convention, because "does the tenant declare this"
 * is the actual question — a rule about capitalisation would be a guess that
 * silently misfiles anything unusual.
 */
function declaredPairs(resourceTypes: ResourceType[]): Set<string> {
  const pairs = new Set<string>();

  for (const resourceType of resourceTypes) {
    for (const action of resourceType.actions) {
      pairs.add(`${resourceType.key}:${action.key}`);
    }
  }

  return pairs;
}

export type SplitPermissions = {
  custom: { action: string; resource: string }[];
  system: PermissionValue[];
};

/**
 * Splits a picker's selection into the two sets the API takes.
 *
 * A selection is custom when the catalogue declares it; everything else is a
 * system permission and goes through untouched.
 */
export function splitPermissions(
  selected: PermissionValue[],
  resourceTypes: ResourceType[],
): SplitPermissions {
  const declared = declaredPairs(resourceTypes);
  const split: SplitPermissions = { custom: [], system: [] };

  for (const value of selected) {
    const entry = Object.entries(value)[0];

    if (!entry) {
      continue;
    }

    const [resource, action] = entry;

    if (declared.has(`${resource}:${action}`)) {
      split.custom.push({ action, resource });
      continue;
    }

    split.system.push(value);
  }

  return split;
}

/// Whether a picker entry came from the tenant's catalogue rather than the
/// platform's fixed set.
export function isCataloguePermission(
  permission: Permission,
  resourceTypes: ResourceType[],
): boolean {
  const entry = Object.entries(permission.value)[0];

  if (!entry) {
    return false;
  }

  return declaredPairs(resourceTypes).has(`${entry[0]}:${entry[1]}`);
}
