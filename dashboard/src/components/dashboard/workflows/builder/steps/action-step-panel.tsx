'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { COMPANY_INTEGRATION } from '@/components/dashboard/workflows/builder/constants';
import {
  PanelAlert,
  PanelField,
  PanelNote,
} from '@/components/dashboard/workflows/builder/panel-field';
import {
  isHighRiskAction,
  getPublishHints,
} from '@/components/dashboard/workflows/builder/step-issues';
import { OperationForm } from '@/components/dashboard/workflows/builder/steps/operation-form';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findLoopOf } from '@/components/dashboard/workflows/builder/working-copy';
import { Select } from '@/components/ui/Select';
import type { WorkflowNode, WorkflowActionStep } from '@/types/workflow-graph';
import type { WorkflowOperation } from '@/types/workflows';

type ActionNode = WorkflowNode & WorkflowActionStep;

function EffectNote({ node }: { node: ActionNode }) {
  const t = useTranslations('dashboard.workflowBuilder.action');
  const { text } = useBuilderContext();
  const effect = text.getEffectText(node.effect);

  if (node.effect === 'read') {
    return <PanelNote icon="visibility">{t('onlyLooks')}</PanelNote>;
  }

  if (isHighRiskAction(node)) {
    return (
      <PanelNote icon="gpp_maybe" tone="danger">
        {t('highRisk', { effect })}
      </PanelNote>
    );
  }

  return (
    <PanelNote icon="edit" tone="warning">
      {t('canAsk', { effect })}
    </PanelNote>
  );
}

export function ActionStepPanel({ disabled, node }: { disabled: boolean; node: ActionNode }) {
  const t = useTranslations('dashboard.workflowBuilder.action');
  const { accounts, accountsReady, lookup, operationsReady, tenantPathFor } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const askBefore = useWorkingCopy((state) => state.askBefore);
  const operation = lookup(node.integration, node.operation);
  const isCompany = node.integration === COMPANY_INTEGRATION;
  const ofIntegration = accounts.filter(
    (account) => account.integration === node.integration && account.status !== 'disabled',
  );
  const isAccountGone =
    accountsReady &&
    Boolean(node.account_id) &&
    !ofIntegration.some((account) => account.id === node.account_id);
  const approvalMissing =
    !findLoopOf(copy.nodes, node.key) &&
    getPublishHints(copy, node, lookup).some((hint) => hint.code === 'approvalMissing');

  function setOperation(next: WorkflowOperation) {
    updateNode(node.key, (current) => ({
      ...current,
      ceiling: next.ceiling,
      effect: next.effect,
      inputs: [],
      operation: next.operation,
    }));
  }

  if (!operation) {
    return operationsReady ? (
      <PanelAlert icon="error" title={t('operationGoneTitle')}>
        {t('operationGone', { operation: node.operation })}
      </PanelAlert>
    ) : (
      <p className="mt-5 text-xs text-textGray">{t('loading')}</p>
    );
  }

  return (
    <>
      {approvalMissing && !disabled ? (
        <PanelAlert
          action={
            <SmallButton
              icon="person_check"
              onClick={() =>
                askBefore(node.key, t('approvalSummary', { step: node.name }), t('approvalName'))
              }
            >
              {t('askFirst')}
            </SmallButton>
          }
          icon="gpp_maybe"
          title={t('needsApprovalTitle')}
        >
          {t('needsApproval')}
        </PanelAlert>
      ) : null}

      {isAccountGone ? (
        <PanelAlert icon="link_off" title={t('accountGoneTitle')}>
          {t('accountGone')}
        </PanelAlert>
      ) : null}

      <PanelField label={t('whatToDo')}>
        <OperationSelect disabled={disabled} node={node} onChange={setOperation} />
      </PanelField>

      {isCompany ? (
        <PanelField hint={t('companyHint')} label={t('actsAs')}>
          <p className="rounded-lg bg-surfaceInset px-3 py-2 text-xs text-white">
            {t('actsAsPerson')}
          </p>
        </PanelField>
      ) : operation.needsAccount ? (
        <PanelField hint={t('accountHint')} label={t('account')} aside={t('required')}>
          {ofIntegration.length > 0 ? (
            <Select
              containerClassName="mb-0"
              disabled={disabled}
              onChange={(value) =>
                updateNode(node.key, (current) => ({ ...current, account_id: value || null }))
              }
              options={ofIntegration.map((account) => ({ label: account.name, value: account.id }))}
              placeholder={t('pickAccount')}
              value={node.account_id ?? ''}
            />
          ) : (
            <Link
              href={tenantPathFor('connected-accounts')}
              className="text-xs font-semibold text-primary hover:underline"
            >
              {t('connectFirst')}
            </Link>
          )}
        </PanelField>
      ) : null}

      <OperationForm
        accountId={node.account_id}
        disabled={disabled}
        inputs={node.inputs}
        onChange={(inputs) => updateNode(node.key, (current) => ({ ...current, inputs }))}
        operation={operation}
        stepKey={node.key}
      />

      <EffectNote node={node} />
    </>
  );
}

function OperationSelect({
  disabled,
  node,
  onChange,
}: {
  disabled: boolean;
  node: ActionNode;
  onChange: (operation: WorkflowOperation) => void;
}) {
  const { lookup, operations } = useBuilderContext();
  const integrationOperations = operations.filter(
    (operation) => operation.integration === node.integration,
  );

  return (
    <Select
      containerClassName="mb-0"
      disabled={disabled}
      onChange={(value) => {
        const next = lookup(node.integration, value);

        if (next) {
          onChange(next);
        }
      }}
      options={integrationOperations.map((operation) => ({
        label: operation.title,
        value: operation.operation,
      }))}
      value={node.operation}
    />
  );
}
