import type { OrgRights } from '@/utils/org-role';

export type SettingsNavItemData = {
  icon: string;
  label: string;
  requires?: keyof OrgRights;
};
