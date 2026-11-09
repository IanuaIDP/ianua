'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import {
  toProposedSteps,
  toProposedTrigger,
} from '@/components/dashboard/workflows/builder/suggestion-to-working-copy';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import {
  WORKFLOW_EXAMPLES,
  type WorkflowExample,
} from '@/components/dashboard/workflows/builder/workflow-examples';
import { getAllStepKeys } from '@/components/dashboard/workflows/builder/working-copy';
import { Checkbox } from '@/components/ui/Checkbox';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { getApiErrorMessage, getTenantModelProviders, suggestWorkflowSteps } from '@/lib/api';
import type { WorkflowProposal } from '@/types/workflow-graph';

const MAX_WORDS = 500;

type BuildForMeModalProps = {
  afterStep?: string;
  onClose: () => void;
};

/** Words become proposed steps. Nothing is saved until the person keeps them. */
export function BuildForMeModal({ afterStep, onClose }: BuildForMeModalProps) {
  const t = useTranslations('dashboard.workflowBuilder.build');
  const tExample = useTranslations('dashboard.workflowBuilder.build.examples');
  const { accounts, flush, lookup, orgSlug, tenantPathFor, tenantSlug, text } = useBuilderContext();
  const workflowId = useWorkingCopy((state) => state.workflowId);
  const nodes = useWorkingCopy((state) => state.copy.nodes);
  const addProposedSteps = useWorkingCopy((state) => state.addProposedSteps);
  const change = useWorkingCopy((state) => state.change);
  const [words, setWords] = useState('');
  const [chosenProvider, setChosenProvider] = useState('');
  const [proposal, setProposal] = useState<WorkflowProposal | null>(null);
  const [keep, setKeep] = useState<Set<string>>(new Set());
  const { data: providers, isSuccess: providersReady } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
  });
  const providerId = chosenProvider || providers?.[0]?.id || '';

  const { error, isPending, mutate } = useMutation({
    mutationFn: async () => {
      if (afterStep) {
        await flush();
      }

      return suggestWorkflowSteps(orgSlug ?? '', tenantSlug, {
        after: afterStep && workflowId ? { step: afterStep, workflowId } : undefined,
        providerId,
        words,
      });
    },
    onSuccess: (answer) => {
      setProposal(answer);
      setKeep(new Set(answer.steps.map((step) => step.key)));
    },
  });

  function keepProposal(chosen: WorkflowProposal, chosenKeep: Set<string>) {
    const { edges, nodes: steps } = toProposedSteps(chosen, {
      accounts,
      after: afterStep ?? null,
      keep: chosenKeep,
      lookup,
      providerId,
      takenKeys: getAllStepKeys(nodes),
    });
    const trigger = afterStep ? null : toProposedTrigger(chosen, accounts);

    if (trigger) {
      change((copy) => ({ ...copy, trigger }));
    }

    addProposedSteps(steps, edges);
    onClose();
  }

  function applyExample(example: WorkflowExample) {
    keepProposal(example.proposal, new Set(example.proposal.steps.map((step) => step.key)));
  }

  function getMissingService(example: WorkflowExample) {
    return example.needs.find(
      (integration) =>
        !accounts.some(
          (account) => account.integration === integration && account.status !== 'disabled',
        ),
    );
  }

  const isEmptyProposal = proposal !== null && proposal.steps.length === 0;
  const canAsk = Boolean(words.trim()) && Boolean(providerId) && !isPending;

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={afterStep ? t('suggestTitle') : t('title')}
      description={t('description')}
      primaryActionLabel={proposal && !isEmptyProposal ? t('keepSelected') : t('build')}
      onPrimaryAction={() => {
        if (proposal && !isEmptyProposal) {
          keepProposal(proposal, keep);

          return;
        }

        mutate();
      }}
      isPrimaryActionDisabled={proposal && !isEmptyProposal ? keep.size === 0 : !canAsk}
      isPrimaryActionLoading={isPending}
    >
      <div className="flex max-h-[60vh] flex-col gap-3 overflow-auto">
        {proposal && !isEmptyProposal ? (
          <div className="flex flex-col gap-2">
            {proposal.steps.map((step) => (
              <Checkbox
                key={step.key}
                checked={keep.has(step.key)}
                id={`proposed-${step.key}`}
                label={`${step.title} (${text.getKindLabel(step.kind)})`}
                onChange={(event) => {
                  const next = new Set(keep);

                  if (event.target.checked) {
                    next.add(step.key);
                  } else {
                    next.delete(step.key);
                  }

                  setKeep(next);
                }}
              />
            ))}
          </div>
        ) : (
          <>
            {providersReady && (providers ?? []).length === 0 ? (
              <Link
                className="text-xs font-semibold text-primary hover:underline"
                href={tenantPathFor('model-providers')}
              >
                {t('noProvider')}
              </Link>
            ) : (
              <Select
                containerClassName="mb-0"
                label={t('model')}
                onChange={setChosenProvider}
                options={(providers ?? []).map((provider) => ({
                  label: `${provider.name} · ${provider.model}`,
                  value: provider.id,
                }))}
                value={providerId}
              />
            )}
            <Textarea
              className="min-h-22"
              containerClassName="mb-0"
              label={t('words')}
              maxLength={MAX_WORDS}
              onChange={(event) => setWords(event.target.value)}
              placeholder={t('wordsExample')}
              value={words}
            />
          </>
        )}

        {isEmptyProposal ? <p className="text-sm text-textGray">{t('nothingProposed')}</p> : null}
        {error ? (
          <p className="text-xs font-medium text-error">{getApiErrorMessage(error, t('failed'))}</p>
        ) : null}
        {proposal?.notes.length ? (
          <div>
            <p className="text-xs font-semibold text-white">{t('notes')}</p>
            <ul className="mt-1 list-disc pl-4 text-xs text-textGray">
              {proposal.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {!afterStep && !proposal ? (
          <div>
            <p className="mb-1 text-xs font-semibold text-white">{t('orExample')}</p>
            <ul className="flex flex-col gap-1">
              {WORKFLOW_EXAMPLES.map((example) => {
                const missing = getMissingService(example);

                return (
                  <li
                    key={example.id}
                    className="flex items-center justify-between gap-2 rounded-lg bg-surfaceInset px-3 py-2 text-sm text-white"
                  >
                    {tExample(example.id)}
                    {missing ? (
                      <Link
                        className="text-xs font-semibold text-primary hover:underline"
                        href={tenantPathFor('connected-accounts')}
                      >
                        {t('connectFirst', { service: text.getIntegrationTitle(missing) })}
                      </Link>
                    ) : (
                      <SmallButton onClick={() => applyExample(example)}>
                        {t('useExample')}
                      </SmallButton>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
