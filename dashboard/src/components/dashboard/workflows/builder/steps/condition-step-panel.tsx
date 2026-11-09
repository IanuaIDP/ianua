'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { MAX_CONDITION_CLAUSES } from '@/components/dashboard/workflows/builder/constants';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { DataPicker } from '@/components/dashboard/workflows/builder/steps/data-picker';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Select } from '@/components/ui/Select';
import type { WorkflowNode, WorkflowClause, WorkflowConditionStep } from '@/types/workflow-graph';
import { cn } from '@/utils/cn';

type ConditionNode = WorkflowNode & WorkflowConditionStep;

const TESTS: WorkflowClause['test'][] = [
  'equals',
  'not_equals',
  'contains',
  'exists',
  'is_empty',
  'greater_than',
  'less_than',
];

function needsValue(test: WorkflowClause['test']) {
  return test !== 'exists' && test !== 'is_empty';
}

function isNumberTest(test: WorkflowClause['test']) {
  return test === 'greater_than' || test === 'less_than';
}

/** A typed value as the test wants it: a number stays a number, anything else is text. */
function parseEqualsValue(raw: string) {
  if (raw.trim() !== '' && !Number.isNaN(Number(raw))) {
    return Number(raw);
  }

  if (raw === 'true' || raw === 'false') {
    return raw === 'true';
  }

  return raw;
}

function ClauseEditor({
  clause,
  disabled,
  onChange,
  onRemove,
  stepKey,
}: {
  clause: WorkflowClause;
  disabled: boolean;
  onChange: (clause: WorkflowClause) => void;
  onRemove: () => void;
  stepKey: string;
}) {
  const t = useTranslations('dashboard.workflowBuilder.condition');
  const [isPicking, setIsPicking] = useState(false);
  const clauseValue = 'value' in clause ? clause.value : undefined;

  function setTest(test: WorkflowClause['test']) {
    if (!needsValue(test)) {
      onChange({ path: clause.path, test } as WorkflowClause);

      return;
    }

    onChange({
      path: clause.path,
      test,
      value: isNumberTest(test) ? 0 : '',
    } as WorkflowClause);
  }

  function setValue(raw: string) {
    if (isNumberTest(clause.test)) {
      onChange({ ...clause, value: raw === '' ? Number.NaN : Number(raw) } as WorkflowClause);

      return;
    }

    onChange({
      ...clause,
      value: clause.test === 'contains' ? raw : parseEqualsValue(raw),
    } as WorkflowClause);
  }

  return (
    <div className="mt-3 rounded-lg bg-surfaceInset p-2.5">
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          disabled={disabled}
          onClick={() => setIsPicking((current) => !current)}
          className={cn(
            'min-w-0 flex-1 truncate rounded-lg px-2.5 py-1.5 text-left text-xs',
            clause.path ? 'bg-primary/15 text-primary' : 'bg-surfaceChip text-textGray',
          )}
        >
          {clause.path || t('pickValue')}
        </button>
        {!disabled ? (
          <button
            type="button"
            aria-label={t('removeClause')}
            onClick={onRemove}
            className="flex size-7 shrink-0 items-center justify-center rounded-md text-textGray hover:text-white"
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              close
            </span>
          </button>
        ) : null}
      </div>
      {isPicking && !disabled ? (
        <DataPicker
          onPick={(path) => {
            onChange({ ...clause, path });
            setIsPicking(false);
          }}
          stepKey={stepKey}
        />
      ) : null}
      <div className="mt-2 grid grid-cols-2 gap-1.5">
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(value) => setTest(value as WorkflowClause['test'])}
          options={TESTS.map((test) => ({ label: t(`tests.${test}`), value: test }))}
          value={clause.test}
        />
        {needsValue(clause.test) ? (
          <Input
            aria-label={t('value')}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setValue(event.target.value)}
            placeholder={t('value')}
            type={isNumberTest(clause.test) ? 'number' : 'text'}
            value={
              clauseValue === undefined ||
              (typeof clauseValue === 'number' && Number.isNaN(clauseValue))
                ? ''
                : String(clauseValue)
            }
          />
        ) : null}
      </div>
    </div>
  );
}

export function ConditionStepPanel({ disabled, node }: { disabled: boolean; node: ConditionNode }) {
  const t = useTranslations('dashboard.workflowBuilder.condition');
  const updateNode = useWorkingCopy((state) => state.updateNode);

  function setClauses(clauses: WorkflowClause[]) {
    updateNode(node.key, (current) => ({ ...current, clauses }));
  }

  return (
    <>
      <PanelField label={t('whenYes')}>
        <SegmentedControl
          ariaLabel={t('whenYes')}
          onChange={(matching) => updateNode(node.key, (current) => ({ ...current, matching }))}
          options={[
            { label: t('all'), value: 'all' },
            { label: t('any'), value: 'any' },
          ]}
          value={node.matching}
        />
      </PanelField>

      {node.clauses.map((clause, index) => (
        <ClauseEditor
          key={index}
          clause={clause}
          disabled={disabled}
          onChange={(next) =>
            setClauses(node.clauses.map((old, position) => (position === index ? next : old)))
          }
          onRemove={() => setClauses(node.clauses.filter((_, position) => position !== index))}
          stepKey={node.key}
        />
      ))}

      {!disabled && node.clauses.length < MAX_CONDITION_CLAUSES ? (
        <SmallButton
          className="mt-3"
          icon="add"
          onClick={() => setClauses([...node.clauses, { path: '', test: 'equals', value: '' }])}
        >
          {t('addClause')}
        </SmallButton>
      ) : null}

      <PanelNote icon="call_split">{t('otherwise')}</PanelNote>
    </>
  );
}
