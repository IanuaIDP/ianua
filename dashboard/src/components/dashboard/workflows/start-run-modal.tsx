'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useTranslations } from 'next-intl';

import { ClearanceSelect } from '@/components/dashboard/workflows/clearance-select';
import { JsonEditor, parseJsonObject } from '@/components/dashboard/workflows/json-editor';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, startWorkflowRun } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { ExposureLevel, Workflow } from '@/types/workflows';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

type StartRunModalProps = {
  onClose: () => void;
  workflow: Workflow | null;
};

/** Starts a by-hand workflow with data the person gives it. */
export function StartRunModal({ onClose, workflow }: StartRunModalProps) {
  const t = useTranslations('dashboard.workflows.startRun');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [inputText, setInputText] = useState('');
  const [exposure, setExposure] = useState<ExposureLevel>('internal');
  const [inputError, setInputError] = useState<string | undefined>();
  const { isPending, mutate } = useMutation({
    mutationFn: (input: Record<string, unknown>) =>
      startWorkflowRun(orgSlug ?? '', tenantSlug, workflow?.id ?? '', { exposure, input }),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async ({ executionId }) => {
      showNotification({ message: t('started'), type: 'success' });
      onClose();
      await queryClient.invalidateQueries({ queryKey: ['workflow-runs', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      router.push(
        getTenantScopedPath(
          isTenantView,
          orgSlug,
          tenantSlug,
          `workflows/runs/${executionId}`,
          `workflows/runs/${executionId}`,
        ),
      );
    },
  });

  function submit() {
    const input = parseJsonObject(inputText);

    if (!input) {
      setInputError(t('invalidJson'));
      return;
    }

    setInputError(undefined);
    mutate(input);
  }

  return (
    <Modal
      open={workflow !== null}
      onClose={onClose}
      title={t('title', { name: workflow?.name ?? '' })}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      onPrimaryAction={submit}
      isPrimaryActionLoading={isPending}
      isPrimaryActionDisabled={isPending}
    >
      <div className="flex flex-col gap-4">
        <JsonEditor
          error={inputError}
          id="workflow-run-input"
          label={t('inputLabel')}
          onChange={setInputText}
          value={inputText}
        />
        <ClearanceSelect label={t('exposureLabel')} onChange={setExposure} value={exposure} />
      </div>
    </Modal>
  );
}
