'use client';

import { createContext, useContext } from 'react';

import type { OperationLookup } from '@/components/dashboard/workflows/builder/step-issues';
import type { useStepText } from '@/components/dashboard/workflows/builder/use-step-text';
import type {
  StepState,
  WorkflowAccount,
  WorkflowIntegration,
  WorkflowOperation,
} from '@/types/workflows';

export type BuilderContextValue = {
  accounts: WorkflowAccount[];
  accountsReady: boolean;
  flush: () => Promise<void>;
  integrations: WorkflowIntegration[];
  isRunView: boolean;
  isTestRun: boolean;
  lookup: OperationLookup;
  operations: WorkflowOperation[];
  operationsReady: boolean;
  orgSlug: string | undefined;
  runSteps: Map<string, StepState> | undefined;
  save: () => Promise<void>;
  tenantPathFor: (segment: string) => string;
  tenantSlug: string;
  text: ReturnType<typeof useStepText>;
};

const BuilderContext = createContext<BuilderContextValue | null>(null);

export const BuilderContextProvider = BuilderContext.Provider;

export function useBuilderContext() {
  const value = useContext(BuilderContext);

  if (!value) {
    throw new Error('The builder context is missing.');
  }

  return value;
}
