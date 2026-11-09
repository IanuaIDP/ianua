'use client';

import { useTranslations } from 'next-intl';

import { PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import type { WorkflowNode } from '@/types/workflow-graph';

/** A kind of step this builder can show but not change yet: it goes back untouched. */
export function OtherStepPanel({ node }: { node: WorkflowNode }) {
  const t = useTranslations('dashboard.workflowBuilder.other');

  return (
    <>
      <PanelNote icon="info">{t('keptAsIs')}</PanelNote>
      <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-surfaceInset p-3 text-xs text-white">
        {JSON.stringify(node, null, 2)}
      </pre>
    </>
  );
}
