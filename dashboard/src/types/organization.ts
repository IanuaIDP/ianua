export type OrganizationStatus = 'Active' | 'Closed' | 'Suspended';

export type Organization = {
  contactEmail: string;
  created: string;
  displayName: string;
  id: string;
  name: string;
  slug: string;
  status: OrganizationStatus;
  tenantsCount: number;
};
