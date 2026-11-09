'use client';

import { useTranslations } from 'next-intl';

import { MAX_BANNED_WORDS } from '@/components/dashboard/workflows/builder/constants';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { PathField } from '@/components/dashboard/workflows/builder/steps/path-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Checkbox } from '@/components/ui/Checkbox';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Select } from '@/components/ui/Select';
import { TagInput } from '@/components/ui/TagInput';
import type { WorkflowGuardrailStep, WorkflowNode } from '@/types/workflow-graph';

type GuardrailNode = WorkflowNode & WorkflowGuardrailStep;

const CHECKS = ['personal_data', 'model_tricks', 'banned_words'] as const;

const LEVELS = ['internal', 'confidential', 'restricted'];

export function GuardrailStepPanel({ disabled, node }: { disabled: boolean; node: GuardrailNode }) {
  const t = useTranslations('dashboard.workflowBuilder.guardrail');
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const change = (patch: Partial<WorkflowGuardrailStep>) =>
    updateNode(node.key, (current) => ({ ...current, ...patch }) as WorkflowNode);

  function toggleCheck(check: string, isOn: boolean) {
    change({
      checks: isOn ? [...node.checks, check] : node.checks.filter((item) => item !== check),
    });
  }

  return (
    <>
      <PanelField hint={t('textHint')} label={t('text')}>
        <PathField
          disabled={disabled}
          onChange={(text) => change({ text })}
          placeholder={t('pickText')}
          stepKey={node.key}
          value={node.text}
        />
      </PanelField>

      <PanelField label={t('checks')}>
        <div className="flex flex-col gap-2">
          {CHECKS.map((check) => (
            <Checkbox
              key={check}
              id={`guardrail-${node.key}-${check}`}
              checked={node.checks.includes(check)}
              disabled={disabled}
              label={t(`checkNames.${check}`)}
              onChange={(event) => toggleCheck(check, event.target.checked)}
            />
          ))}
        </div>
      </PanelField>

      {node.checks.includes('personal_data') ? (
        <PanelField label={t('personalFrom')}>
          <Select
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(personal_from) => change({ personal_from })}
            options={LEVELS.map((value) => ({ label: t(`levels.${value}` as never), value }))}
            value={node.personal_from ?? 'confidential'}
          />
        </PanelField>
      ) : null}

      {node.checks.includes('banned_words') ? (
        <PanelField hint={t('bannedHint', { most: MAX_BANNED_WORDS })} label={t('bannedWords')}>
          <TagInput
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(banned_words) => change({ banned_words })}
            value={node.banned_words ?? []}
          />
        </PanelField>
      ) : null}

      <PanelField label={t('onFinding')}>
        <SegmentedControl
          ariaLabel={t('onFinding')}
          onChange={(on_finding) => {
            if (!disabled) {
              change({ on_finding });
            }
          }}
          options={[
            { label: t('stop'), value: 'stop' },
            { label: t('remove'), value: 'remove' },
            { label: t('record'), value: 'record' },
          ]}
          value={node.on_finding ?? 'stop'}
        />
      </PanelField>

      <PanelNote icon="shield">{t('handsOn')}</PanelNote>
    </>
  );
}
