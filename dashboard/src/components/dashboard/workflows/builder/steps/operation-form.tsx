'use client';

import { useTranslations } from 'next-intl';

import type { PickerTarget } from '@/components/dashboard/workflows/builder/steps/picker-field';
import { StepPreview } from '@/components/dashboard/workflows/builder/steps/step-preview';
import {
  ValueField,
  type ValueBlock,
} from '@/components/dashboard/workflows/builder/steps/value-field';
import {
  getMappedSource,
  setMappedSource,
} from '@/components/dashboard/workflows/builder/mapped-fields';
import type { WorkflowMappedField, WorkflowSource } from '@/types/workflow-graph';
import type { OperationInput, WorkflowOperation } from '@/types/workflows';

type OperationFormProps = {
  accountId: string | null;
  disabled: boolean;
  inputs: WorkflowMappedField[];
  onChange: (inputs: WorkflowMappedField[]) => void;
  operation: WorkflowOperation;
  stepKey: string;
};

function toValueBlock(input: OperationInput): ValueBlock {
  switch (input.form?.block) {
    case 'long_text':
    case 'number':
    case 'switch':
    case 'choices':
    case 'multi_picker':
    case 'key_values':
    case 'picker':
    case 'app_picker':
    case 'data_picker':
    case 'memory_picker':
      return input.form.block;
    default:
      return 'text';
  }
}

export function OperationForm({
  accountId,
  disabled,
  inputs,
  onChange,
  operation,
  stepKey,
}: OperationFormProps) {
  const t = useTranslations('dashboard.workflowBuilder.action');
  const isFolded = (input: OperationInput) =>
    !input.required && input.form?.group === 'more_options';
  const main = operation.inputs.filter((input) => !isFolded(input));
  const folded = operation.inputs.filter(isFolded);

  function setSource(field: string, source: WorkflowSource | undefined) {
    onChange(setMappedSource(inputs, field, source));
  }

  function getPickerTarget(input: OperationInput): PickerTarget {
    const parentName = input.form?.picker?.dependsOn ?? null;
    const parent = parentName ? getMappedSource(inputs, parentName) : undefined;
    const parentInput = operation.inputs.find((item) => item.name === parentName);

    return {
      accountId,
      dependsOn: parentName
        ? {
            label: parentInput?.form?.label ?? parentName,
            value: parent?.from === 'literal' ? parent.value : undefined,
          }
        : null,
      input: input.name,
      integration: operation.integration,
      operation: operation.operation,
    };
  }

  function renderInput(input: OperationInput) {
    return (
      <ValueField
        key={input.name}
        aside={input.required ? t('required') : undefined}
        block={toValueBlock(input)}
        choices={input.form?.choices}
        disabled={disabled}
        example={input.form?.example ?? undefined}
        hint={input.description || undefined}
        isMonospace={input.form?.style === 'monospace'}
        isTall={input.form?.style === 'tall'}
        label={input.form?.label ?? input.name}
        onChange={(source) => setSource(input.name, source)}
        pickerTarget={getPickerTarget(input)}
        source={getMappedSource(inputs, input.name)}
        stepKey={stepKey}
        warning={input.form?.warning ?? undefined}
      />
    );
  }

  return (
    <>
      {main.map(renderInput)}
      {folded.length > 0 ? (
        <details className="mt-5 border-t border-borderGray pt-3">
          <summary className="cursor-pointer text-xs text-textGray">{t('moreOptions')}</summary>
          {folded.map(renderInput)}
        </details>
      ) : null}
      {operation.preview ? <StepPreview inputs={inputs} preview={operation.preview} /> : null}
    </>
  );
}
