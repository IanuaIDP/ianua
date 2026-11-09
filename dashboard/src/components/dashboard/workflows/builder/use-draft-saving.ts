'use client';

import { useCallback, useEffect, useRef } from 'react';
import { useTranslations } from 'next-intl';

import {
  getDraftEdits,
  getSendableGraph,
  toNewWorkflow,
} from '@/components/dashboard/workflows/builder/draft-saving';
import {
  clearDraftStash,
  writeDraftStash,
} from '@/components/dashboard/workflows/builder/draft-stash';
import type { OperationLookup } from '@/components/dashboard/workflows/builder/step-issues';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { createBuilderWorkflow, editWorkflowDraft, getApiErrorMessage } from '@/lib/api';
import type { Workflow } from '@/types/workflows';

const SAVE_DELAY_MS = 800;
const MOST_EDITS_AT_ONCE = 16;

type DraftSavingOptions = {
  isCatalogReady: boolean;
  lookup: OperationLookup;
  onCreated: (workflow: Workflow) => void;
  orgSlug: string | undefined;
  tenantSlug: string;
};

function isDraftInSync(lookup: OperationLookup) {
  const { copy, saved } = useWorkingCopy.getState();

  if (!saved) {
    return false;
  }

  return getDraftEdits(copy, saved, lookup).length === 0 && hasNothingUnsent(lookup);
}

function hasNothingUnsent(lookup: OperationLookup) {
  const { copy, saved } = useWorkingCopy.getState();

  return getSendableGraph(copy, saved, lookup).unsent.length === 0;
}

/** Writes the working copy to the draft by itself, and keeps what is not saved for this tab. */
export function useDraftSaving({
  isCatalogReady,
  lookup,
  onCreated,
  orgSlug,
  tenantSlug,
}: DraftSavingOptions) {
  const t = useTranslations('dashboard.workflowBuilder');
  const timer = useRef<number | null>(null);
  const isRunning = useRef(false);
  const shouldRunAgain = useRef(false);
  const isManualSave = useRef(false);
  const latest = useRef({ isCatalogReady, lookup, onCreated });

  useEffect(() => {
    latest.current = { isCatalogReady, lookup, onCreated };
  });

  const applyEdits = useCallback(
    async (slug: string, workflowId: string, currentLookup: OperationLookup) => {
      const store = useWorkingCopy;

      for (let count = 0; count < MOST_EDITS_AT_ONCE; count += 1) {
        const { copy, saved } = store.getState();

        if (!saved) {
          return;
        }

        const [next] = getDraftEdits(copy, saved, currentLookup);

        if (!next) {
          return;
        }

        const answer = await editWorkflowDraft(slug, tenantSlug, workflowId, next.edit);

        store.getState().markSaved(next.next, answer.revision);
      }
    },
    [tenantSlug],
  );

  const createFirst = useCallback(
    async (slug: string) => {
      const { copy } = useWorkingCopy.getState();
      const body = toNewWorkflow(copy, latest.current.lookup, {
        allowEmpty: isManualSave.current,
        isCatalogReady: latest.current.isCatalogReady,
      });

      if (!body) {
        if (isManualSave.current) {
          throw new Error(t('save.needsNameAndSchedule'));
        }

        return;
      }

      const created = await createBuilderWorkflow(slug, tenantSlug, body);

      writeDraftStash(slug, tenantSlug, created.id, {
        baseRevision: created.revision,
        copy: useWorkingCopy.getState().copy,
      });
      clearDraftStash(slug, tenantSlug, null);
      latest.current.onCreated(created);
    },
    [t, tenantSlug],
  );

  const saveNow = useCallback(async () => {
    if (isRunning.current) {
      shouldRunAgain.current = true;

      return;
    }

    isRunning.current = true;

    do {
      shouldRunAgain.current = false;

      const state = useWorkingCopy.getState();
      const canSendWithoutCatalog = isManualSave.current && !state.workflowId;

      if (!orgSlug || !state.editable) {
        break;
      }

      if (!latest.current.isCatalogReady && !canSendWithoutCatalog) {
        state.setSaveStatus(
          isManualSave.current ? 'failed' : 'idle',
          isManualSave.current ? t('save.catalogNotReady') : null,
        );
        break;
      }

      state.setSaveStatus('saving');

      try {
        if (state.workflowId) {
          await applyEdits(orgSlug, state.workflowId, latest.current.lookup);
        } else {
          await createFirst(orgSlug);
        }

        useWorkingCopy.getState().setSaveStatus('idle');
      } catch (error) {
        useWorkingCopy
          .getState()
          .setSaveStatus('failed', getApiErrorMessage(error, t('saveFailed')));
        shouldRunAgain.current = false;
      }
    } while (shouldRunAgain.current);

    isRunning.current = false;
    isManualSave.current = false;
  }, [applyEdits, createFirst, orgSlug, t]);

  const updateStash = useCallback(() => {
    if (!orgSlug) {
      return;
    }

    const { copy, revision, saved, workflowId } = useWorkingCopy.getState();

    if (saved && isDraftInSync(latest.current.lookup)) {
      clearDraftStash(orgSlug, tenantSlug, workflowId);

      return;
    }

    writeDraftStash(orgSlug, tenantSlug, workflowId, { baseRevision: revision, copy });
  }, [orgSlug, tenantSlug]);

  useEffect(() => {
    const stop = useWorkingCopy.subscribe((state, previous) => {
      if (state.saved !== previous.saved && state.editable) {
        updateStash();
      }

      if (state.copy === previous.copy || !state.editable) {
        return;
      }

      updateStash();
      state.setSaveStatus('pending');

      if (timer.current) {
        window.clearTimeout(timer.current);
      }

      timer.current = window.setTimeout(() => void saveNow(), SAVE_DELAY_MS);
    });

    return () => {
      stop();

      if (timer.current) {
        window.clearTimeout(timer.current);
      }
    };
  }, [saveNow, updateStash]);

  /** Sends what is waiting and resolves once it is saved, or has failed to. */
  const flush = useCallback(async () => {
    if (timer.current) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }

    await saveNow();
    await waitUntilIdle(isRunning);
  }, [saveNow]);

  /** The Save button: like `flush`, and a new workflow is created even with no finished step. */
  const save = useCallback(async () => {
    isManualSave.current = true;
    await flush();
  }, [flush]);

  return { flush, save };
}

async function waitUntilIdle(isRunning: { current: boolean }) {
  while (isRunning.current) {
    await new Promise((resolve) => window.setTimeout(resolve, 40));
  }
}
