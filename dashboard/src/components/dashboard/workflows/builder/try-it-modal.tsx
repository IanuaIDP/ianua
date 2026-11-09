'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { getSendableGraph } from '@/components/dashboard/workflows/builder/draft-saving';
import { PanelAlert } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { ClearanceSelect } from '@/components/dashboard/workflows/clearance-select';
import { JsonEditor, parseJsonObject } from '@/components/dashboard/workflows/json-editor';
import { Modal } from '@/components/ui/modal';
import { getApiErrorMessage, startWorkflowTest } from '@/lib/api';
import type { ExposureLevel } from '@/types/workflows';

type TryItModalProps = {
  onClose: () => void;
  onStarted: (runId: string) => void;
};

/** Tests the saved draft on example data. Nothing outside changes. */
export function TryItModal({ onClose, onStarted }: TryItModalProps) {
  const t = useTranslations('dashboard.workflowBuilder.tryIt');
  const { flush, lookup, orgSlug, tenantSlug } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const saved = useWorkingCopy((state) => state.saved);
  const [input, setInput] = useState('{\n  \n}');
  const [exposure, setExposure] = useState<ExposureLevel>('internal');
  const parsed = parseJsonObject(input);
  const { unsent } = getSendableGraph(copy, saved, lookup);
  const { error, isPending, mutate } = useMutation({
    mutationFn: async () => {
      await flush();

      const { workflowId } = useWorkingCopy.getState();

      return startWorkflowTest(orgSlug ?? '', tenantSlug, workflowId ?? '', {
        exposure,
        input: parsed,
      });
    },
    onSuccess: (runId) => {
      onStarted(runId);
      onClose();
    },
  });

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={t('title')}
      description={t('description')}
      primaryActionLabel={t('start')}
      onPrimaryAction={() => mutate()}
      isPrimaryActionDisabled={parsed === null || unsent.length > 0}
      isPrimaryActionLoading={isPending}
    >
      <div className="flex flex-col gap-3">
        <JsonEditor
          error={parsed === null ? t('notJson') : undefined}
          id="try-it-input"
          label={t('input')}
          onChange={setInput}
          value={input}
        />
        <ClearanceSelect label={t('exposure')} onChange={setExposure} value={exposure} />
        {unsent.length > 0 ? (
          <PanelAlert icon="edit_note" title={t('unfinished', { count: unsent.length })}>
            {unsent.map((node) => (
              <p key={node.key}>{node.name}</p>
            ))}
          </PanelAlert>
        ) : null}
        {error ? (
          <p className="text-xs font-medium text-error">{getApiErrorMessage(error, t('failed'))}</p>
        ) : null}
      </div>
    </Modal>
  );
}
