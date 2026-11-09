'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import {
  ACTION_CLASSES,
  MAX_AGENT_STEPS,
} from '@/components/dashboard/workflows/builder/constants';
import { getStepsBefore } from '@/components/dashboard/workflows/builder/graph';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { MappedFieldsEditor } from '@/components/dashboard/workflows/builder/steps/mapped-fields-editor';
import { MoneyInput } from '@/components/dashboard/workflows/builder/steps/money-input';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Input } from '@/components/ui/Input';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { getTenantAgents, getTenantModelProviders, getTenantTools } from '@/lib/api';
import type { WorkflowAgentRunStep, WorkflowNode } from '@/types/workflow-graph';

type AgentNode = WorkflowNode & WorkflowAgentRunStep;

const CLASS_OPTIONS = ACTION_CLASSES.filter((value) => value !== 'undeclared');

export function AgentStepPanel({ disabled, node }: { disabled: boolean; node: AgentNode }) {
  const t = useTranslations('dashboard.workflowBuilder.agent');
  const { orgSlug, tenantSlug, text } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const change = (patch: Partial<WorkflowAgentRunStep>) =>
    updateNode(node.key, (current) => ({ ...current, ...patch }) as WorkflowNode);
  const { data: agents } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-agents', orgSlug, tenantSlug],
  });
  const { data: providers } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
  });
  const { data: tools } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getTenantTools(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-tools', orgSlug, tenantSlug],
  });
  const before = getStepsBefore(copy.edges, node.key);
  const canCheck = copy.nodes.filter(
    (step): step is AgentNode =>
      step.kind === 'agent_run' && before.has(step.key) && step.agent_id !== node.agent_id,
  );
  const classOptions = CLASS_OPTIONS.map((value) => ({
    label: text.getEffectText(value),
    value,
  }));
  const isChecking = Boolean(node.checks);

  return (
    <>
      <PanelField label={t('agent')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(agent_id) => change({ agent_id })}
          options={(agents ?? []).map((agent) => ({ label: agent.name, value: agent.id }))}
          placeholder={t('pickAgent')}
          value={node.agent_id}
        />
      </PanelField>

      <PanelField label={t('provider')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(provider_id) => change({ provider_id })}
          options={(providers ?? []).map((provider) => ({
            label: `${provider.name} · ${provider.model}`,
            value: provider.id,
          }))}
          placeholder={t('pickProvider')}
          value={node.provider_id}
        />
      </PanelField>

      <PanelField hint={t('goalHint')} label={t('goal')}>
        <Textarea
          aria-label={t('goal')}
          className="min-h-22"
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(event) => change({ goal: event.target.value })}
          value={node.goal}
        />
      </PanelField>

      <MappedFieldsEditor
        disabled={disabled}
        fields={node.inputs}
        label={t('inputs')}
        onChange={(inputs) => change({ inputs })}
        stepKey={node.key}
      />

      <PanelField hint={t('checksHint')} label={t('checks')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(value) =>
            change({ checks: value || undefined, tools: value ? [] : node.tools })
          }
          options={[
            { label: t('notChecking'), value: '' },
            ...canCheck.map((step) => ({ label: step.name, value: step.key })),
          ]}
          value={node.checks ?? ''}
        />
      </PanelField>

      {isChecking ? <PanelNote icon="reviews">{t('checkingNote')}</PanelNote> : null}

      {!isChecking ? (
        <PanelField label={t('tools')}>
          <MultiSelect
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(next) => change({ tools: next })}
            options={(tools ?? []).map((tool) => ({ label: tool.name, value: tool.name }))}
            value={node.tools ?? []}
          />
        </PanelField>
      ) : null}

      <PanelField hint={t('purposeHint')} label={t('purpose')}>
        <MultiSelect
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(purpose) => change({ purpose })}
          options={classOptions}
          value={node.purpose ?? []}
        />
      </PanelField>

      <PanelField hint={t('approvalClassesHint')} label={t('approvalClasses')}>
        <MultiSelect
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(approval_classes) => change({ approval_classes })}
          options={classOptions}
          value={node.approval_classes ?? []}
        />
      </PanelField>

      <PanelField hint={t('maxStepsHint', { most: MAX_AGENT_STEPS })} label={t('maxSteps')}>
        <Input
          aria-label={t('maxSteps')}
          containerClassName="mb-0"
          disabled={disabled}
          max={MAX_AGENT_STEPS}
          min={1}
          onChange={(event) => change({ max_steps: Number(event.target.value) })}
          type="number"
          value={String(node.max_steps)}
        />
      </PanelField>

      <div className="mt-5 grid grid-cols-2 gap-2">
        <MoneyInput
          disabled={disabled}
          label={t('spendCap')}
          onChange={(spend_cap_micros) => change({ spend_cap_micros })}
          placeholder={t('noLimit')}
          value={node.spend_cap_micros}
        />
        <MoneyInput
          disabled={disabled}
          label={t('askPast')}
          onChange={(ask_past_micros) => change({ ask_past_micros })}
          placeholder={t('neverAsk')}
          value={node.ask_past_micros}
        />
      </div>
      <PanelNote icon="payments">{t('spendHelp')}</PanelNote>
    </>
  );
}
