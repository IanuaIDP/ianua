'use client';

import { useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { BuildForMeModal } from '@/components/dashboard/workflows/builder/build-for-me-modal';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import {
  PanelAlert,
  PanelField,
  PanelNote,
} from '@/components/dashboard/workflows/builder/panel-field';
import {
  getPublishHints,
  getStepIssues,
} from '@/components/dashboard/workflows/builder/step-issues';
import { StepMark } from '@/components/dashboard/workflows/builder/step-mark';
import { ActionStepPanel } from '@/components/dashboard/workflows/builder/steps/action-step-panel';
import { AgentStepPanel } from '@/components/dashboard/workflows/builder/steps/agent-step-panel';
import { CodeStepPanel } from '@/components/dashboard/workflows/builder/steps/code-step-panel';
import { GuardrailStepPanel } from '@/components/dashboard/workflows/builder/steps/guardrail-step-panel';
import { LoopStepPanel } from '@/components/dashboard/workflows/builder/steps/loop-step-panel';
import { ApprovalStepPanel } from '@/components/dashboard/workflows/builder/steps/approval-step-panel';
import { ConditionStepPanel } from '@/components/dashboard/workflows/builder/steps/condition-step-panel';
import { OtherStepPanel } from '@/components/dashboard/workflows/builder/steps/other-step-panel';
import { TransformStepPanel } from '@/components/dashboard/workflows/builder/steps/transform-step-panel';
import { WaitStepPanel } from '@/components/dashboard/workflows/builder/steps/wait-step-panel';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { JsonView } from '@/components/dashboard/workflows/json-view';
import { WithheldNotice } from '@/components/dashboard/workflows/withheld-notice';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { findStep } from '@/components/dashboard/workflows/builder/working-copy';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { WorkflowNode, WorkflowJoin } from '@/types/workflow-graph';

type PanelTab = 'failure' | 'result' | 'setup';

function renderSetup(node: WorkflowNode, disabled: boolean) {
  switch (node.kind) {
    case 'action':
      return <ActionStepPanel disabled={disabled} node={node} />;
    case 'condition':
      return <ConditionStepPanel disabled={disabled} node={node} />;
    case 'transform':
      return <TransformStepPanel disabled={disabled} node={node} />;
    case 'approval':
      return <ApprovalStepPanel disabled={disabled} node={node} />;
    case 'wait':
      return <WaitStepPanel disabled={disabled} node={node} />;
    case 'agent_run':
      return <AgentStepPanel disabled={disabled} node={node} />;
    case 'guardrail':
      return <GuardrailStepPanel disabled={disabled} node={node} />;
    case 'loop':
      return <LoopStepPanel disabled={disabled} node={node} />;
    case 'code':
      return <CodeStepPanel disabled={disabled} node={node} />;
    default:
      return <OtherStepPanel node={node} />;
  }
}

function StepResult({ node }: { node: WorkflowNode }) {
  const t = useTranslations('dashboard.workflowBuilder.result');
  const { isTestRun, lookup, runSteps } = useBuilderContext();
  const state = runSteps?.get(node.key);

  if (state?.withheld) {
    return (
      <div className="mt-5">
        <WithheldNotice />
      </div>
    );
  }

  const operation = node.kind === 'action' ? lookup(node.integration, node.operation) : null;
  const output = state?.output as { stood_in?: boolean; would_use?: unknown } | null | undefined;

  return (
    <>
      {isTestRun && node.kind === 'approval' && state ? (
        <PanelNote icon="person_check">{t('approvalInTest')}</PanelNote>
      ) : null}
      {state?.failure ? (
        <PanelAlert icon="error" title={t('failed')} tone="danger">
          <code>{state.failure.code}</code>
          {state.failure.detail ? `: ${state.failure.detail}` : ''}
        </PanelAlert>
      ) : null}
      {output?.stood_in ? (
        <PanelField hint={t('stoodInHint')} label={t('stoodIn')}>
          <JsonView value={output.would_use} />
        </PanelField>
      ) : output !== null && output !== undefined ? (
        <PanelField label={t('fromRun')}>
          <JsonView value={output} />
        </PanelField>
      ) : null}
      <PanelField label={t('laterCanUse')}>
        {operation && operation.outputs.length > 0 ? (
          <ul className="flex flex-col gap-1">
            {operation.outputs.map((item) => (
              <li key={item.path} className="text-xs text-textGray">
                <code className="text-primary">{`${node.key}.${item.path}`}</code>
                {item.description ? ` — ${item.description}` : ''}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-textGray">
            {node.kind === 'condition' || node.kind === 'wait' || node.kind === 'approval'
              ? t('nothing')
              : t('wholeOutput', { key: node.key })}
          </p>
        )}
      </PanelField>
    </>
  );
}

function StepFailure({ node }: { node: WorkflowNode }) {
  const t = useTranslations('dashboard.workflowBuilder.failure');
  const failureAlert = useWorkingCopy((state) => state.copy.failureAlert);

  return (
    <>
      <PanelNote icon="error">{t('stops')}</PanelNote>
      {node.kind === 'action' ? <PanelNote icon="autorenew">{t('tries')}</PanelNote> : null}
      <PanelNote icon="notifications">
        {failureAlert === 'also_authors' ? t('toldAuthors') : t('toldAdministrators')}
      </PanelNote>
    </>
  );
}

function JoinField({ disabled, node }: { disabled: boolean; node: WorkflowNode }) {
  const t = useTranslations('dashboard.workflowBuilder.panel');
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const edges = useWorkingCopy((state) => state.copy.edges);
  const arrowsIn = edges.filter((edge) => edge.to === node.key).length;

  if (arrowsIn < 2) {
    return null;
  }

  return (
    <PanelField hint={t('joinHint')} label={t('join')}>
      <SegmentedControl<WorkflowJoin>
        ariaLabel={t('join')}
        onChange={(join) => {
          if (!disabled) {
            updateNode(node.key, (current) => ({ ...current, join }));
          }
        }}
        options={[
          { label: t('joinAll'), value: 'all' },
          { label: t('joinAny'), value: 'any' },
        ]}
        value={node.join ?? 'all'}
      />
    </PanelField>
  );
}

export function StepPanel({ stepKey }: { stepKey: string }) {
  const t = useTranslations('dashboard.workflowBuilder.panel');
  const tIssues = useLooseTranslations('dashboard.workflowBuilder.issues');
  const { integrations, lookup, operationsReady, text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const editable = useWorkingCopy((state) => state.editable);
  const remember = useWorkingCopy((state) => state.remember);
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const removeSelected = useWorkingCopy((state) => state.removeSelected);
  const [tab, setTab] = useState<PanelTab>('setup');
  const [isSuggesting, setIsSuggesting] = useState(false);
  const workflowId = useWorkingCopy((state) => state.workflowId);
  const node = findStep(copy.nodes, stepKey);
  const isInLoop = Boolean(node && !copy.nodes.some((item) => item.key === stepKey));
  const disabled = !editable;
  const hints = useMemo(() => {
    if (!node || !operationsReady) {
      return [];
    }

    const issues = isInLoop ? getStepIssues(node, lookup) : getPublishHints(copy, node, lookup);

    return issues.filter((hint) => hint.code !== 'approvalMissing');
  }, [copy, isInLoop, lookup, node, operationsReady]);

  if (!node) {
    return null;
  }

  const integration =
    node.kind === 'action'
      ? (integrations.find((item) => item.key === node.integration) ?? null)
      : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col" onFocusCapture={remember}>
      <div className="px-4 pt-4">
        <div className="flex items-start gap-2.5">
          <StepMark integration={integration} node={node} />
          <textarea
            aria-label={t('stepName')}
            className="min-w-0 flex-1 resize-none rounded-lg border border-transparent bg-transparent px-1.5 py-1 text-base font-bold text-white outline-none [field-sizing:content] enabled:hover:bg-hoverBg focus:border-focus"
            disabled={disabled}
            onChange={(event) =>
              updateNode(node.key, (current) => ({
                ...current,
                name: event.target.value.replace(/\n/g, ' '),
              }))
            }
            rows={1}
            value={node.name}
          />
          {!disabled ? (
            <button
              type="button"
              aria-label={t('remove')}
              title={t('remove')}
              onClick={() => removeSelected(node.key)}
              className="flex size-8 shrink-0 items-center justify-center rounded-lg text-textGray transition hover:bg-hoverBg hover:text-white"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                delete
              </span>
            </button>
          ) : null}
        </div>
        <p className="mt-2 text-xs text-textGray">{text.getKindHelp(node.kind)}</p>
      </div>

      <div className="px-4 pt-3">
        <SegmentedControl<PanelTab>
          ariaLabel={t('tabs')}
          onChange={setTab}
          options={[
            { label: t('setup'), value: 'setup' },
            { label: t('result'), value: 'result' },
            { label: t('ifItFails'), value: 'failure' },
          ]}
          value={tab}
        />
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-4 pb-5">
        {tab === 'setup' ? (
          <>
            {hints.length > 0 && !disabled ? (
              <PanelAlert icon="error" title={t('toFinish', { count: hints.length })}>
                {hints.map((hint) => (
                  <p key={`${hint.code}-${hint.values?.field ?? ''}`}>
                    {tIssues(hint.code, hint.values)}
                  </p>
                ))}
              </PanelAlert>
            ) : null}
            {renderSetup(node, disabled)}
            <JoinField disabled={disabled} node={node} />
            {!disabled && !isInLoop && workflowId ? (
              <div className="mt-5">
                <SmallButton icon="wand_stars" onClick={() => setIsSuggesting(true)}>
                  {t('suggestNext')}
                </SmallButton>
              </div>
            ) : null}
          </>
        ) : null}
        {tab === 'result' ? <StepResult node={node} /> : null}
        {tab === 'failure' ? <StepFailure node={node} /> : null}
      </div>
      {isSuggesting ? (
        <BuildForMeModal afterStep={node.key} onClose={() => setIsSuggesting(false)} />
      ) : null}
    </div>
  );
}
