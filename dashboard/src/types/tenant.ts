import type { TenantResidency } from '@/types/cloud-account';

export type TenantStatus = 'Provisioning' | 'Active' | 'Suspended' | 'Archived';

export type TenantTab = 'All' | TenantStatus;

export type TenantSortField = 'created_at' | 'display_name' | 'updated_at';

export type TenantSortDirection = 'asc' | 'desc';

export type TenantAction = 'Suspend' | 'Archive' | 'Restore Access' | 'Delete forever';

export type Tenant = {
  id: number | string;
  name: string;
  slug: string;
  status: TenantStatus;
  created: string;
  deletableFrom: string | null;
};

export type TenantList = {
  items: Tenant[];
  limit: number;
  nextCursor: string | null;
};

export type TenantDetail = {
  contactEmail: string;
  created: string;
  displayName: string;
  environment: string | null;
  id: string;
  locale: string;
  loginUrl: string | null;
  organizationId: string;
  primaryDomain: string | null;
  residency: TenantResidency;
  slug: string;
  status: TenantStatus;
  timezone: string;
  updated: string;
};
