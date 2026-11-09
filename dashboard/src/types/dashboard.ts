import type { ReactNode } from 'react';

export type DashboardActionModalContent = {
  confirmationLabel?: string;
  confirmationPlaceholder?: string;
  confirmationValue?: string;
  description: ReactNode;
  primaryActionLabel: string;
  secondaryActionLabel?: string;
  title: string;
  warningNote?: string;
  warningTone?: 'caution' | 'danger';
};

export type DashboardNavItem = {
  activeMatch?: 'exact' | 'nested';
  group?: string;
  href: string;
  icon: string;
  isActive?: boolean;
  label: string;
};

export type NavSegment =
  | { type: 'item'; item: DashboardNavItem }
  | { type: 'group'; group: string; items: DashboardNavItem[] };

export type SelectOption = {
  label: string;
  value: string;
};
