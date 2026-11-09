import type { DataClassLevel } from '@/types/classification';

/**
 * One verb a resource type accepts, and what holding it confers.
 *
 * `grants` arrives with the ladder already walked by the API, so nothing here
 * expands it and no screen can disagree with the proxy about what a grant
 * means.
 */
export type ResourceAction = {
  displayName: string;
  grants: string[];
  implies: string[];
  key: string;
};

/**
 * A kind of thing a tenant's own application protects.
 *
 * The declaration that roles and routes check themselves against. Without it
 * a custom permission is free text at every point of use, so `project:write`
 * and `projects:write` become two permissions and nothing says which was
 * meant.
 */
export type ResourceType = {
  actions: ResourceAction[];
  created: string;
  dataClass: DataClassLevel;
  description: string | null;
  displayName: string;
  id: string;
  key: string;
};

export type ResourceTypeList = {
  items: ResourceType[];
  limit: number;
  nextCursor: string | null;
};

export type ResourceTypeSortField = 'key' | 'created_at' | 'updated_at';

export type ResourceTypeSortDirection = 'asc' | 'desc';

export type ResourceTypeAction = 'Edit' | 'Delete';
