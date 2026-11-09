import type { ExposureLevel } from '@/types/workflows';

export type Memory = {
  clearance: ExposureLevel | string;
  createdAt: string;
  createdBy: string;
  deletedAfter: string | null;
  embeddingModel: string;
  embeddingSource: string;
  id: string;
  name: string;
  providerId: string | null;
  status: string;
  updatedAt: string;
  vectorSize: number;
};

export type MemoryEntry = {
  exposure: ExposureLevel | string;
  id: string;
  keptAt: string;
  text: string;
};

export type MemoryEntryPage = {
  entries: MemoryEntry[];
  nextCursor: string | null;
};

export type CreateMemoryInput = {
  clearance: ExposureLevel;
  name: string;
  providerId: string | null;
};
