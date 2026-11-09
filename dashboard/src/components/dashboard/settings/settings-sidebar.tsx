import { SettingsNavItemData } from '@/types/setting';
import type { OrgRights } from '@/utils/org-role';

export const settingsNavItems: SettingsNavItemData[] = [
  { icon: 'tune', label: 'General' },
  { icon: 'person', label: 'Account' },
  { icon: 'encrypted', label: 'Security' },
  { icon: 'login', label: 'Sign-in', requires: 'canManageOrganization' },
  { icon: 'key', label: 'API Key', requires: 'canManageOrganization' },
  { icon: 'cloud', label: 'Cloud', requires: 'canManageOrganization' },
  { icon: 'credit_card', label: 'Subscription', requires: 'canViewBilling' },
  { icon: 'article', label: 'Audit Log', requires: 'canViewAuditLog' },
  { icon: 'dangerous', label: 'Danger zone', requires: 'canManageOrganization' },
];

export function getVisibleSettingsNavItems(rights: OrgRights) {
  return settingsNavItems.filter((item) => !item.requires || rights[item.requires]);
}
