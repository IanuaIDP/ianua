'use client';

import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import {
  MAX_LOOP_AT_ONCE,
  MAX_LOOP_ITEMS,
} from '@/components/dashboard/workflows/builder/constants';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { MappedFieldsEditor } from '@/components/dashboard/workflows/builder/steps/mapped-fields-editor';
import { PathField } from '@/components/dashboard/workflows/builder/steps/path-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import type { WorkflowLoopStep, WorkflowNode } from '@/types/workflow-graph';

type LoopNode = WorkflowNode & WorkflowLoopStep;

export function LoopStepPanel({ disabled, node }: { disabled: boolean; node: LoopNode }) {
  const t = useTranslations('dashboard.workflowBuilder.loop');
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const openDrawer = useWorkingCopy((state) => state.openDrawer);
  const select = useWorkingCopy((state) => state.select);
  const change = (patch: Partial<WorkflowLoopStep>) =>
    updateNode(node.key, (current) => ({ ...current, ...patch }) as WorkflowNode);

  return (
    <>
      <PanelField hint={t('overHint')} label={t('over')}>
        <PathField
          disabled={disabled}
          onChange={(over) => change({ over })}
          placeholder={t('pickList')}
          stepKey={node.key}
          value={node.over}
        />
      </PanelField>

      <div className="mt-5 grid grid-cols-2 gap-2">
        <Input
          containerClassName="mb-0"
          disabled={disabled}
          hint={t('mostItemsHint', { most: MAX_LOOP_ITEMS })}
          label={t('mostItems')}
          max={MAX_LOOP_ITEMS}
          min={1}
          onChange={(event) => change({ most_items: Number(event.target.value) })}
          type="number"
          value={String(node.most_items)}
        />
        <Input
          containerClassName="mb-0"
          disabled={disabled}
          hint={t('atOnceHint', { most: MAX_LOOP_AT_ONCE })}
          label={t('atOnce')}
          max={MAX_LOOP_AT_ONCE}
          min={1}
          onChange={(event) => change({ at_once: Number(event.target.value) })}
          type="number"
          value={String(node.at_once)}
        />
      </div>

      <MappedFieldsEditor
        disabled={disabled}
        fields={node.inputs}
        label={t('inputs')}
        onChange={(inputs) => change({ inputs })}
        stepKey={node.key}
      />

      <PanelField label={t('inside')}>
        <ul className="flex flex-col gap-1">
          {node.steps.nodes.map((inner) => (
            <li key={inner.key}>
              <button
                type="button"
                onClick={() => select({ key: inner.key, type: 'step' })}
                className="w-full truncate rounded-lg bg-surfaceInset px-3 py-1.5 text-left text-xs text-white hover:bg-hoverBg"
              >
                {inner.name}
              </button>
            </li>
          ))}
        </ul>
        {!disabled ? (
          <SmallButton
            className="mt-2"
            icon="add"
            onClick={() => openDrawer({ intoLoop: node.key })}
          >
            {t('addInside')}
          </SmallButton>
        ) : null}
      </PanelField>

      <PanelNote icon="repeat">{t('insideReads')}</PanelNote>
    </>
  );
}
