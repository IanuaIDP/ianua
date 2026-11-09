'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { getDraftChanges } from '@/components/dashboard/workflows/builder/draft-diff';
import { getSendableGraph } from '@/components/dashboard/workflows/builder/draft-saving';
import { PanelAlert } from '@/components/dashboard/workflows/builder/panel-field';
import { findStep } from '@/components/dashboard/workflows/builder/working-copy';
import { getPublishHints } from '@/components/dashboard/workflows/builder/step-issues';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { getTouchedPlaces } from '@/components/dashboard/workflows/builder/what-it-touches';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import {
  getApiErrorMessage,
  getBuilderWorkflow,
  getWorkflowRefusalKey,
  publishWorkflowDraft,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { WorkflowGraph, WorkflowTrigger } from '@/types/workflow-graph';

const CHANGED_SINCE = 'workflows-the-draft-changed-since-it-was';
const HIGH_RISK_REFUSAL = 'workflows-is-a-high-risk-action-without';
const GATE_REFUSAL = 'workflows-the-draft-must-pass-its-evaluation';

const CHANGE_ICONS = {
  add: 'add_circle',
  edit: 'edit',
  follow: 'edit',
  remove: 'remove_circle',
  rename: 'edit',
  trigger: 'edit',
};

const CHANGE_TONES = {
  add: 'text-green',
  edit: 'text-primary',
  follow: 'text-primary',
  remove: 'text-error',
  rename: 'text-primary',
  trigger: 'text-primary',
};

type PublishSheetProps = {
  onClose: () => void;
  onPublished: () => void;
  onReload: () => Promise<void>;
};

type InService = { graph: WorkflowGraph; trigger: WorkflowTrigger } | null;

function findNamedStep(message: string, keys: string[]) {
  return (
    keys.find((key) =>
      new RegExp(`(^|[^a-z0-9_-])${key.replace(/[-]/g, '\\-')}([^a-z0-9_-]|$)`).test(message),
    ) ?? null
  );
}

export function PublishSheet({ onClose, onPublished, onReload }: PublishSheetProps) {
  const t = useTranslations('dashboard.workflowBuilder.publish');
  const tIssues = useLooseTranslations('dashboard.workflowBuilder.issues');
  const tVerb = useLooseTranslations('dashboard.workflowBuilder.touches.verbs');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { flush, lookup, orgSlug, tenantPathFor, tenantSlug, text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const workflowId = useWorkingCopy((state) => state.workflowId);
  const version = useWorkingCopy((state) => state.version);
  const saved = useWorkingCopy((state) => state.saved);
  const saveStatus = useWorkingCopy((state) => state.saveStatus);
  const saveError = useWorkingCopy((state) => state.saveError);
  const select = useWorkingCopy((state) => state.select);
  const askBefore = useWorkingCopy((state) => state.askBefore);
  const [refusal, setRefusal] = useState<{ key: string | null; message: string } | null>(null);
  const [isReviewing, setIsReviewing] = useState(true);

  useEffect(() => {
    void flush().finally(() => setIsReviewing(false));
  }, [flush]);

  const { data: inService } = useQuery({
    enabled: Boolean(orgSlug && workflowId) && version > 1,
    queryFn: async (): Promise<InService> => {
      const previous = await getBuilderWorkflow(
        orgSlug ?? '',
        tenantSlug,
        workflowId ?? '',
        version - 1,
      );

      return previous.status === 'published'
        ? { graph: previous.graph, trigger: previous.trigger }
        : null;
    },
    queryKey: ['workflow-in-service', orgSlug, tenantSlug, workflowId, version],
  });

  const changes = getDraftChanges(copy, inService ?? null);
  const places = getTouchedPlaces(copy);
  const hints = copy.nodes.flatMap((node) =>
    getPublishHints(copy, node, lookup).map((hint) => ({ hint, node })),
  );
  const { unsent } = getSendableGraph(copy, saved, lookup);
  const cannotPublish =
    !workflowId ||
    isReviewing ||
    saveStatus === 'failed' ||
    copy.nodes.length === 0 ||
    unsent.length > 0;

  const { isPending, mutate: submitPublish } = useMutation({
    mutationFn: () => {
      const { revision } = useWorkingCopy.getState();

      return publishWorkflowDraft(orgSlug ?? '', tenantSlug, workflowId ?? '', revision ?? '');
    },
    onError: async (error) => {
      const key = getWorkflowRefusalKey(error);

      setRefusal({ key, message: getApiErrorMessage(error, t('failed')) });

      if (key === CHANGED_SINCE) {
        await onReload();
      }
    },
    onSuccess: async () => {
      showNotification({ message: t('turnedOn'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['workflows', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onPublished();
      onClose();
    },
  });

  const refusedStep = refusal
    ? findNamedStep(
        refusal.message,
        copy.nodes.map((node) => node.key),
      )
    : null;

  function focusStep(key: string) {
    onClose();
    select({ key, type: 'step' });
  }

  function askFirst(key: string) {
    const name = findStep(copy.nodes, key)?.name ?? key;

    askBefore(key, t('approvalSummary', { step: name }), t('approvalName'));
    onClose();
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={t('title')}
      description={t('description')}
      primaryActionLabel={t('turnOn')}
      onPrimaryAction={() => {
        setRefusal(null);
        submitPublish();
      }}
      isPrimaryActionDisabled={cannotPublish}
      isPrimaryActionLoading={isPending}
    >
      <div className="flex max-h-[60vh] flex-col gap-2 overflow-auto">
        {changes.length === 0 ? <p className="text-sm text-textGray">{t('noChanges')}</p> : null}
        {changes.map((change, index) => (
          <div
            key={index}
            className="flex items-start gap-2.5 rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white"
          >
            <span
              className={`material-symbols-rounded text-lg! ${CHANGE_TONES[change.kind]}`}
              aria-hidden="true"
            >
              {CHANGE_ICONS[change.kind]}
            </span>
            <span>{t(`changes.${change.kind}`, change as never)}</span>
          </div>
        ))}

        <p className="mt-3 text-xs font-semibold uppercase tracking-wide text-textGray">
          {t('canTouch')}
        </p>
        {places.length === 0 ? (
          <p className="text-sm text-textGray">{t('touchesNothing')}</p>
        ) : null}
        {places.map((place) => (
          <p
            key={`${place.verb}-${place.integration}`}
            className="rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white"
          >
            <span className="text-textGray">{tVerb(place.verb)}: </span>
            {text.getIntegrationTitle(place.integration)}
          </p>
        ))}

        {unsent.length > 0 ? (
          <PanelAlert icon="edit_note" title={t('notSavedTitle', { count: unsent.length })}>
            {unsent.map((node) => (
              <p key={node.key}>{node.name}</p>
            ))}
          </PanelAlert>
        ) : null}

        {saveStatus === 'failed' && saveError ? (
          <PanelAlert icon="error" title={t('saveFailed')} tone="danger">
            {saveError}
          </PanelAlert>
        ) : null}

        {hints.length > 0 ? (
          <PanelAlert icon="error" title={t('hintsTitle', { count: hints.length })}>
            <p className="mb-1">{t('hintsHelp')}</p>
            {hints.map(({ hint, node }) => (
              <p key={`${node.key}-${hint.code}-${hint.values?.field ?? ''}`}>
                <button
                  type="button"
                  className="font-semibold text-white hover:underline"
                  onClick={() => focusStep(node.key)}
                >
                  {node.name}
                </button>
                {': '}
                {tIssues(hint.code, hint.values)}
              </p>
            ))}
          </PanelAlert>
        ) : null}

        {refusal ? (
          <PanelAlert
            action={
              <>
                {refusedStep ? (
                  <SmallButton onClick={() => focusStep(refusedStep)}>{t('showStep')}</SmallButton>
                ) : null}
                {refusal.key === GATE_REFUSAL && workflowId ? (
                  <Link
                    className="inline-flex items-center rounded-lg bg-surfaceChip px-3 py-1.5 text-xs font-semibold text-white hover:bg-borderGray"
                    href={tenantPathFor(`workflows/${workflowId}/evaluations`)}
                  >
                    {t('openEvaluations')}
                  </Link>
                ) : null}
                {refusal.key === HIGH_RISK_REFUSAL && refusedStep ? (
                  <SmallButton icon="person_check" onClick={() => askFirst(refusedStep)}>
                    {t('askFirst')}
                  </SmallButton>
                ) : null}
              </>
            }
            icon="block"
            title={refusal.key === CHANGED_SINCE ? t('changedTitle') : t('refusedTitle')}
            tone="danger"
          >
            {refusal.message}
          </PanelAlert>
        ) : null}
      </div>
    </Modal>
  );
}
