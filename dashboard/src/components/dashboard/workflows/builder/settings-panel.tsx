'use client';

import { useTranslations } from 'next-intl';

import { MAX_RUN_LIMIT_SECONDS } from '@/components/dashboard/workflows/builder/constants';
import { PanelField } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import type { WorkflowFailureAlert } from '@/types/workflow-graph';

const SECONDS_PER_HOUR = 3_600;

/** The workflow's own settings: its description, how long a run may take, who hears of failures. */
export function SettingsPanel() {
  const t = useTranslations('dashboard.workflowBuilder.settings');
  const copy = useWorkingCopy((state) => state.copy);
  const editable = useWorkingCopy((state) => state.editable);
  const change = useWorkingCopy((state) => state.change);
  const remember = useWorkingCopy((state) => state.remember);

  return (
    <div className="flex-1 overflow-auto p-4" onFocusCapture={remember}>
      <p className="text-base font-bold text-white">{t('title')}</p>

      <PanelField hint={t('descriptionHint')} label={t('description')}>
        <Textarea
          aria-label={t('description')}
          className="min-h-22"
          containerClassName="mb-0"
          disabled={!editable}
          maxLength={500}
          onChange={(event) =>
            change((current) => ({ ...current, description: event.target.value }), false)
          }
          value={copy.description}
        />
      </PanelField>

      <PanelField hint={t('runLimitHint')} label={t('runLimit')}>
        <Input
          aria-label={t('runLimit')}
          containerClassName="mb-0"
          disabled={!editable}
          max={MAX_RUN_LIMIT_SECONDS / SECONDS_PER_HOUR}
          min={0}
          onChange={(event) =>
            change(
              (current) => ({
                ...current,
                runLimitSeconds: Math.round(Number(event.target.value) * SECONDS_PER_HOUR),
              }),
              false,
            )
          }
          step="any"
          type="number"
          value={String(copy.runLimitSeconds / SECONDS_PER_HOUR)}
        />
      </PanelField>

      <PanelField label={t('failureAlert')}>
        <Select
          containerClassName="mb-0"
          disabled={!editable}
          onChange={(value) =>
            change((current) => ({ ...current, failureAlert: value as WorkflowFailureAlert }))
          }
          options={[
            { label: t('administrators'), value: 'administrators' },
            { label: t('alsoAuthors'), value: 'also_authors' },
          ]}
          value={copy.failureAlert}
        />
      </PanelField>
    </div>
  );
}
