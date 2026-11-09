import type { DataClassLevel } from '@/types/classification';

export type ToolMethod = 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';

export type ToolStatus = 'Active' | 'Disabled';

export type ToolAction = 'Delete' | 'Disable tool' | 'Enable tool';

export type Tool = {
  actionClass: string;
  classification: DataClassLevel;
  description: string;
  id: string;
  method: ToolMethod;
  name: string;
  path: string;
  routeId: string;
  schema: Record<string, unknown>;
  status: ToolStatus;
};
