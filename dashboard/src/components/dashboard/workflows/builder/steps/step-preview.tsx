'use client';

import { useTranslations } from 'next-intl';

import { PanelField } from '@/components/dashboard/workflows/builder/panel-field';
import { getMappedSource } from '@/components/dashboard/workflows/builder/mapped-fields';
import type { WorkflowMappedField } from '@/types/workflow-graph';
import type { OperationPreview } from '@/types/workflows';

function getPartText(fields: WorkflowMappedField[], input: string) {
  const source = getMappedSource(fields, input);

  if (!source) {
    return '';
  }

  if (source.from === 'input') {
    return `{${source.path}}`;
  }

  return Array.isArray(source.value) ? source.value.join(', ') : String(source.value ?? '');
}

/** What the step will send, shaped by the kind of thing it makes, with the values typed so far. */
export function StepPreview({
  inputs,
  preview,
}: {
  inputs: WorkflowMappedField[];
  preview: OperationPreview;
}) {
  const t = useTranslations('dashboard.workflowBuilder.preview');
  const part = (name: string) => {
    const found = preview.parts.find((item) => item.part === name);

    return found ? getPartText(inputs, found.input) : '';
  };
  const lines: [string, string][] = [
    [t('place'), part('place')],
    [t('sender'), part('sender')],
    [t('titleLine'), part('title')],
    [t('status'), part('status')],
    [t('labels'), part('labels')],
    [t('start'), part('start')],
    [t('end'), part('end')],
  ];

  return (
    <PanelField label={t('heading')}>
      <div className="rounded-lg bg-surfaceInset p-3 text-xs text-white">
        {lines
          .filter(([, value]) => value)
          .map(([label, value]) => (
            <p key={label}>
              <span className="text-textGray">{label}: </span>
              {value}
            </p>
          ))}
        {part('body') ? <p className="mt-1.5 whitespace-pre-wrap">{part('body')}</p> : null}
      </div>
    </PanelField>
  );
}
