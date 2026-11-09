'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { TRIGGER_KEY } from '@/components/dashboard/workflows/builder/constants';
import { PanelField } from '@/components/dashboard/workflows/builder/panel-field';
import { DataPicker } from '@/components/dashboard/workflows/builder/steps/data-picker';
import {
  PickerField,
  TargetPicker,
  type PickerTarget,
} from '@/components/dashboard/workflows/builder/steps/picker-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findStep } from '@/components/dashboard/workflows/builder/working-copy';
import { Input } from '@/components/ui/Input';
import { Switch } from '@/components/ui/Switch';
import { TagInput } from '@/components/ui/TagInput';
import { Textarea } from '@/components/ui/Textarea';
import type { WorkflowSource } from '@/types/workflow-graph';
import type { OperationChoice } from '@/types/workflows';
import { cn } from '@/utils/cn';

const CHOICE_TONES: Record<string, string> = {
  danger: 'bg-error/15 text-error',
  info: 'bg-focus/15 text-focus',
  neutral: 'bg-primary/15 text-primary',
  success: 'bg-green/15 text-green',
  warning: 'bg-orange/15 text-orange',
};

export type ValueBlock =
  | 'app_picker'
  | 'choices'
  | 'data_picker'
  | 'key_values'
  | 'long_text'
  | 'memory_picker'
  | 'multi_picker'
  | 'number'
  | 'picker'
  | 'switch'
  | 'text';

type ValueFieldProps = {
  aside?: string;
  block: ValueBlock;
  choices?: OperationChoice[];
  disabled: boolean;
  example?: string;
  hint?: string;
  isMonospace?: boolean;
  isTall?: boolean;
  label: string;
  onChange: (source: WorkflowSource | undefined) => void;
  pickerTarget?: PickerTarget;
  source: WorkflowSource | undefined;
  stepKey: string;
  warning?: string;
};

function toKeyValues(value: unknown): [string, string][] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }

  return Object.entries(value).map(([key, item]) => [key, String(item ?? '')]);
}

function toTags(value: unknown) {
  return Array.isArray(value) ? value.map(String) : [];
}

function DataToken({
  disabled,
  onClear,
  path,
}: {
  disabled: boolean;
  onClear: () => void;
  path: string;
}) {
  const t = useTranslations('dashboard.workflowBuilder.picker');
  const nodes = useWorkingCopy((state) => state.copy.nodes);
  const [root, ...rest] = path.split('.');
  const title = root === TRIGGER_KEY ? t('trigger') : (findStep(nodes, root)?.name ?? root);

  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded-full bg-primary/15 py-0.5 pl-2 pr-1 text-xs text-primary">
      <span className="material-symbols-rounded text-sm!" aria-hidden="true">
        data_object
      </span>
      <span className="min-w-0 truncate" title={path}>
        <span className="opacity-70">{title}</span>
        {rest.length > 0 ? ` · ${rest.join('.')}` : ''}
      </span>
      <button
        type="button"
        disabled={disabled}
        aria-label={t('clear')}
        onClick={onClear}
        className="flex size-5 shrink-0 items-center justify-center rounded-full hover:bg-primary/20 disabled:hidden"
      >
        <span className="material-symbols-rounded text-sm!" aria-hidden="true">
          close
        </span>
      </button>
    </span>
  );
}

/** One field that takes a typed value or earlier data, never a mix of both. */
export function ValueField({
  aside,
  block,
  choices = [],
  disabled,
  example,
  hint,
  isMonospace,
  isTall,
  label,
  onChange,
  pickerTarget,
  source,
  stepKey,
  warning,
}: ValueFieldProps) {
  const t = useTranslations('dashboard.workflowBuilder.picker');
  const [isPicking, setIsPicking] = useState(false);
  const literal = source?.from === 'literal' ? source.value : undefined;

  function setLiteral(value: unknown) {
    onChange(value === '' || value === undefined ? undefined : { from: 'literal', value });
  }

  function handlePick(path: string) {
    onChange({ from: 'input', path });
    setIsPicking(false);
  }

  function renderLiteral() {
    const textClassName = cn(isMonospace && 'font-mono text-xs');

    switch (block) {
      case 'long_text':
        return (
          <Textarea
            aria-label={label}
            className={cn(textClassName, isTall ? 'min-h-40' : 'min-h-22')}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setLiteral(event.target.value)}
            placeholder={example}
            value={typeof literal === 'string' ? literal : ''}
          />
        );
      case 'number':
        return (
          <Input
            aria-label={label}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) =>
              setLiteral(event.target.value === '' ? undefined : Number(event.target.value))
            }
            placeholder={example}
            type="number"
            value={typeof literal === 'number' ? String(literal) : ''}
          />
        );
      case 'switch':
        return (
          <Switch
            aria-label={label}
            checked={literal === true}
            disabled={disabled}
            onCheckedChange={setLiteral}
          />
        );
      case 'choices':
        return (
          <div className="flex flex-wrap gap-1.5">
            {choices.map((choice) => {
              const isActive = literal === choice.value;

              return (
                <button
                  key={choice.value}
                  type="button"
                  disabled={disabled}
                  aria-pressed={isActive}
                  onClick={() => setLiteral(isActive ? undefined : choice.value)}
                  className={cn(
                    'rounded-full px-3 py-1 text-xs font-medium transition disabled:opacity-60',
                    isActive
                      ? (CHOICE_TONES[choice.tone] ?? CHOICE_TONES.neutral)
                      : 'bg-surfaceChip text-textGray hover:text-white',
                  )}
                >
                  {choice.label}
                </button>
              );
            })}
          </div>
        );
      case 'app_picker':
      case 'data_picker':
      case 'memory_picker':
        return (
          <TargetPicker
            block={block}
            disabled={disabled}
            label={label}
            onChange={setLiteral}
            value={literal}
          />
        );
      case 'picker':
        return pickerTarget ? (
          <PickerField
            disabled={disabled}
            example={example}
            isMulti={false}
            label={label}
            onChange={setLiteral}
            target={pickerTarget}
            value={literal}
          />
        ) : null;
      case 'multi_picker':
        return pickerTarget ? (
          <PickerField
            disabled={disabled}
            example={example}
            isMulti
            label={label}
            onChange={(value) =>
              setLiteral(Array.isArray(value) && value.length === 0 ? undefined : value)
            }
            target={pickerTarget}
            value={literal}
          />
        ) : (
          <TagInput
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(tags) => setLiteral(tags.length > 0 ? tags : undefined)}
            placeholder={example}
            value={toTags(literal)}
          />
        );
      case 'key_values':
        return (
          <KeyValuesEditor
            disabled={disabled}
            onChange={(entries) =>
              setLiteral(entries.length > 0 ? Object.fromEntries(entries) : undefined)
            }
            value={toKeyValues(literal)}
          />
        );
      default:
        return (
          <Input
            aria-label={label}
            className={textClassName}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setLiteral(event.target.value)}
            placeholder={example}
            value={typeof literal === 'string' ? literal : ''}
          />
        );
    }
  }

  return (
    <PanelField
      aside={aside}
      hint={hint}
      label={
        <span className="flex items-center gap-1.5">
          {label}
          {!disabled ? (
            <button
              type="button"
              onClick={() => setIsPicking((current) => !current)}
              aria-expanded={isPicking}
              aria-label={t('useEarlier', { field: label })}
              title={t('useEarlierHint')}
              className={cn(
                'flex items-center rounded p-0.5 transition',
                isPicking ? 'bg-primary/15 text-primary' : 'text-textGray hover:text-white',
              )}
            >
              <span className="material-symbols-rounded text-base!" aria-hidden="true">
                data_object
              </span>
            </button>
          ) : null}
        </span>
      }
    >
      {source?.from === 'input' ? (
        <DataToken disabled={disabled} onClear={() => onChange(undefined)} path={source.path} />
      ) : (
        renderLiteral()
      )}
      {isPicking && !disabled ? <DataPicker onPick={handlePick} stepKey={stepKey} /> : null}
      {warning ? (
        <p className="mt-1.5 flex gap-1 text-xs text-orange">
          <span className="material-symbols-rounded text-sm!" aria-hidden="true">
            warning
          </span>
          {warning}
        </p>
      ) : null}
    </PanelField>
  );
}

function KeyValuesEditor({
  disabled,
  onChange,
  value,
}: {
  disabled: boolean;
  onChange: (entries: [string, string][]) => void;
  value: [string, string][];
}) {
  const t = useTranslations('dashboard.workflowBuilder.picker');
  const rows: [string, string][] = [...value, ['', '']];

  function setRow(index: number, next: [string, string]) {
    const updated = rows.map((row, position) => (position === index ? next : row));

    onChange(updated.filter(([key]) => key.trim() !== ''));
  }

  return (
    <div className="flex flex-col gap-1.5">
      {rows.map(([key, item], index) => (
        <div key={index} className="grid grid-cols-2 gap-1.5">
          <Input
            aria-label={t('name')}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setRow(index, [event.target.value, item])}
            placeholder={t('name')}
            value={key}
          />
          <Input
            aria-label={t('value')}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setRow(index, [key, event.target.value])}
            placeholder={t('value')}
            value={item}
          />
        </div>
      ))}
    </div>
  );
}
