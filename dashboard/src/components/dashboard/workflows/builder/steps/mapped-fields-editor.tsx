'use client';

import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { MAX_MAPPED_FIELDS } from '@/components/dashboard/workflows/builder/constants';
import { isValidFieldName } from '@/components/dashboard/workflows/builder/mapped-fields';
import { PanelField } from '@/components/dashboard/workflows/builder/panel-field';
import { ValueField } from '@/components/dashboard/workflows/builder/steps/value-field';
import { Input } from '@/components/ui/Input';
import type { WorkflowMappedField } from '@/types/workflow-graph';

type MappedFieldsEditorProps = {
  disabled: boolean;
  fields: WorkflowMappedField[];
  label: string;
  onChange: (fields: WorkflowMappedField[]) => void;
  stepKey: string;
};

/** A list of named fields, each a typed value or one piece of earlier data. */
export function MappedFieldsEditor({
  disabled,
  fields,
  label,
  onChange,
  stepKey,
}: MappedFieldsEditorProps) {
  const t = useTranslations('dashboard.workflowBuilder.transform');

  function replaceField(index: number, next: WorkflowMappedField) {
    onChange(fields.map((field, position) => (position === index ? next : field)));
  }

  return (
    <>
      {fields.map((field, index) => (
        <div key={index} className="mt-4 rounded-lg bg-surfaceInset p-2.5">
          <div className="flex items-center gap-1.5">
            <Input
              aria-label={t('fieldName')}
              containerClassName="mb-0 flex-1"
              disabled={disabled}
              error={field.field && !isValidFieldName(field.field) ? t('fieldNameRule') : undefined}
              onChange={(event) => replaceField(index, { ...field, field: event.target.value })}
              placeholder={t('fieldName')}
              value={field.field}
            />
            {!disabled ? (
              <button
                type="button"
                aria-label={t('removeField')}
                onClick={() => onChange(fields.filter((_, position) => position !== index))}
                className="flex size-7 shrink-0 items-center justify-center rounded-md text-textGray hover:text-white"
              >
                <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                  close
                </span>
              </button>
            ) : null}
          </div>
          <ValueField
            block="text"
            disabled={disabled}
            label={t('value')}
            onChange={(source) =>
              replaceField(index, {
                ...(source ?? { from: 'literal', value: '' }),
                field: field.field,
              } as WorkflowMappedField)
            }
            source={field}
            stepKey={stepKey}
          />
        </div>
      ))}

      {!disabled && fields.length < MAX_MAPPED_FIELDS ? (
        <PanelField label={label}>
          <SmallButton
            icon="add"
            onClick={() => onChange([...fields, { field: '', from: 'literal', value: '' }])}
          >
            {t('addField')}
          </SmallButton>
        </PanelField>
      ) : null}
    </>
  );
}
