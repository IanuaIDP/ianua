'use client';

import { useTranslations } from 'next-intl';

import { MappedFieldsEditor } from '@/components/dashboard/workflows/builder/steps/mapped-fields-editor';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import type { WorkflowNode, WorkflowTransformStep } from '@/types/workflow-graph';

type TransformNode = WorkflowNode & WorkflowTransformStep;

export function TransformStepPanel({ disabled, node }: { disabled: boolean; node: TransformNode }) {
  const t = useTranslations('dashboard.workflowBuilder.transform');
  const updateNode = useWorkingCopy((state) => state.updateNode);

  return (
    <MappedFieldsEditor
      disabled={disabled}
      fields={node.fields}
      label={t('fields')}
      onChange={(fields) => updateNode(node.key, (current) => ({ ...current, fields }))}
      stepKey={node.key}
    />
  );
}
