'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { JsonEditor, parseJsonObject } from '@/components/dashboard/workflows/json-editor';
import { JsonView } from '@/components/dashboard/workflows/json-view';
import { WriteCodeModal } from '@/components/dashboard/workflows/sandboxes/write-code-modal';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  getApiErrorMessage,
  getApiErrorStatus,
  getSandboxTrial,
  startSandboxTrial,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { SandboxVersion, WrittenSandboxCode } from '@/types/sandbox';

type TrialPanelProps = {
  onFixed: (written: WrittenSandboxCode) => void;
  sandboxId: string;
  version: SandboxVersion;
};

/** Tries a built version on sample input and shows what came back or why it failed. */
export function TrialPanel({ onFixed, sandboxId, version }: TrialPanelProps) {
  const t = useTranslations('dashboard.sandboxes.trial');
  const tFailure = useLooseTranslations('dashboard.sandboxes.trial.failures');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [inputText, setInputText] = useState('');
  const [inputError, setInputError] = useState<string | undefined>();
  const [trialId, setTrialId] = useState<string | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const { isPending, mutate } = useMutation({
    mutationFn: (input: Record<string, unknown>) =>
      startSandboxTrial(orgSlug ?? '', tenantSlug, sandboxId, version.id, input),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async (trial) => {
      setTrialId(trial.id);
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });
  const { data: trial, error } = useQuery({
    enabled: Boolean(trialId),
    queryFn: () => getSandboxTrial(orgSlug ?? '', tenantSlug, sandboxId, trialId ?? ''),
    queryKey: ['sandbox-trial', orgSlug, tenantSlug, sandboxId, trialId],
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 3_000 : false),
    retry: false,
  });

  function start() {
    const input = parseJsonObject(inputText);

    if (!input) {
      setInputError(t('invalidJson'));
      return;
    }

    setInputError(undefined);
    mutate(input);
  }

  const isRunning = isPending || trial?.status === 'running';
  const failureCode = trial?.failure?.code ?? '';
  const failure = trial?.failure
    ? tFailure.has(failureCode)
      ? tFailure(failureCode)
      : failureCode
    : null;
  const failureText = trial?.failure?.detail
    ? `${failure}: ${trial.failure.detail}`
    : (failure ?? '');

  return (
    <div className="mt-4 flex flex-col gap-3 border-t border-borderGray pt-4">
      <h3 className="text-xs font-semibold text-white">{t('title')}</h3>
      {version.agent ? <p className="text-xs text-textGray">{t('checkOnly')}</p> : null}
      <JsonEditor
        error={inputError}
        id={`sandbox-trial-input-${version.id}`}
        label={t('input')}
        onChange={setInputText}
        value={inputText}
      />
      <div className="flex justify-end">
        <Button disabled={isRunning} isLoading={isRunning} type="button" onClick={start}>
          {t('start')}
        </Button>
      </div>

      {error ? (
        <p className="text-xs text-textGray">
          {getApiErrorStatus(error) === 404
            ? t('gone')
            : getApiErrorMessage(error, t('readFailed'))}
        </p>
      ) : null}

      {trial?.status === 'running' ? <p className="text-xs text-textGray">{t('running')}</p> : null}

      {trial?.status === 'succeeded' ? <JsonView value={trial.output} /> : null}

      {trial?.status === 'failed' ? (
        <div className="flex flex-col gap-2">
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error">
            {failureText}
          </p>
          {version.code ? (
            <div className="flex justify-end">
              <Button type="button" variant="outline" onClick={() => setIsFixing(true)}>
                {t('fix')}
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}

      <WriteCodeModal
        fix={{ code: version.code ?? '', failure: failureText }}
        open={isFixing}
        packages={version.packages.map((item) => item.name)}
        sandboxId={sandboxId}
        onClose={() => setIsFixing(false)}
        onWritten={(written) => {
          setIsFixing(false);
          onFixed(written);
        }}
      />
    </div>
  );
}
