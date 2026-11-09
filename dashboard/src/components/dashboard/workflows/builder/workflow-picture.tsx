'use client';

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { StepMark } from '@/components/dashboard/workflows/builder/step-mark';
import { useStepText } from '@/components/dashboard/workflows/builder/use-step-text';
import type { BuilderSelection } from '@/components/dashboard/workflows/builder/use-working-copy';
import { WorkflowCanvas } from '@/components/dashboard/workflows/builder/workflow-canvas';
import { toWorkingCopy } from '@/components/dashboard/workflows/builder/working-copy';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getWorkflowIntegrations } from '@/lib/api';
import type { WorkflowNode } from '@/types/workflow-graph';
import type { Execution, Workflow } from '@/types/workflows';

type WorkflowPictureProps = {
  onSelectStep?: (key: string | null) => void;
  run?: Execution;
  workflow: Workflow;
};

/** A version as a read-only picture, each step coloured by a run when one is given. */
export function WorkflowPicture({ onSelectStep, run, workflow }: WorkflowPictureProps) {
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const [selection, setSelection] = useState<BuilderSelection>(null);
  const copy = useMemo(() => toWorkingCopy(workflow), [workflow]);
  const runSteps = useMemo(
    () => (run ? new Map(run.steps.map((state) => [state.key, state])) : undefined),
    [run],
  );
  const { data: integrations } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getWorkflowIntegrations(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-integrations', orgSlug, tenantSlug],
  });
  const text = useStepText(integrations);

  function describeStep(node: WorkflowNode | null) {
    if (!node) {
      return {
        line: text.getTriggerLine(copy.trigger),
        mark: <StepMark trigger={copy.trigger} />,
        title: text.getTriggerTitle(copy.trigger),
      };
    }

    const integration =
      node.kind === 'action'
        ? (integrations?.find((item) => item.key === node.integration) ?? null)
        : null;

    return {
      line: text.getStepLine(node),
      mark: <StepMark integration={integration} node={node} />,
      title: node.name,
    };
  }

  return (
    <WorkflowCanvas
      key={workflow.version}
      copy={copy}
      describeStep={describeStep}
      onSelect={(next) => {
        setSelection(next);
        onSelectStep?.(next?.type === 'step' ? next.key : null);
      }}
      runSteps={runSteps}
      selection={selection}
    />
  );
}
