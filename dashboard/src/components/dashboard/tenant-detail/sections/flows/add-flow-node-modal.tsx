'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { MoneyInput } from '@/components/dashboard/workflows/builder/steps/money-input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { RangeSlider } from '@/components/ui/RangeSlider';
import { Select } from '@/components/ui/Select';
import { Textarea } from '@/components/ui/Textarea';
import { useToolOptions } from '@/hooks/dashboard/use-tool-options';
import { FlowNodeFormSchema, type FlowNodeFormInput } from '@/schemas/flow-schemas';
import type { ModelProvider } from '@/types/model-provider';
import type { FlowNodeDraft } from '@/types/flow-builder';
import type { TenantAgent } from '@/types/tenant-agent';
import type { Tool } from '@/types/tool';

type AddFlowNodeModalProps = {
  agents: TenantAgent[];
  initialNode?: FlowNodeDraft | null;
  open: boolean;
  providers: ModelProvider[];
  tools: Tool[];
  onClose: () => void;
  onSubmit: (node: FlowNodeDraft) => void;
};

const addFlowNodeFormId = 'add-flow-node-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: FlowNodeFormInput = {
  agentId: '',
  approvalClasses: [],
  goal: '',
  maxSteps: 8,
  providerId: '',
  purpose: [],
  toolNames: [],
};

function toDefaultValues(node?: FlowNodeDraft | null): FlowNodeFormInput {
  if (!node) {
    return defaultValues;
  }

  return {
    agentId: node.agentId,
    approvalClasses: node.approvalClasses,
    goal: node.goal,
    maxSteps: node.maxSteps,
    spendCapMicros: node.spendCapMicros,
    askPastMicros: node.askPastMicros,
    providerId: node.providerId,
    purpose: node.purpose,
    toolNames: node.toolNames,
  };
}

export function AddFlowNodeModal({
  agents,
  initialNode,
  open,
  providers,
  tools,
  onClose,
  onSubmit,
}: AddFlowNodeModalProps) {
  const t = useTranslations('dashboard.flows.nodeModal');
  const { actionClassOptions } = useToolOptions();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<FlowNodeFormInput>({
    resolver: zodResolver(FlowNodeFormSchema),
    defaultValues,
  });

  useEffect(() => {
    if (open) {
      reset(toDefaultValues(initialNode));
    }
  }, [initialNode, open, reset]);

  const purpose = useWatch({ control, name: 'purpose' });
  const approvalClasses = useWatch({ control, name: 'approvalClasses' });
  const maxSteps = useWatch({ control, name: 'maxSteps' });

  useEffect(() => {
    const filtered = approvalClasses.filter((value) => purpose.includes(value));

    if (filtered.length !== approvalClasses.length) {
      setValue('approvalClasses', filtered);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [purpose]);

  const activeAgents = agents.filter((agent) => agent.status === 'Active');
  const activeProviders = providers.filter((provider) => provider.status === 'Active');
  const activeTools = tools.filter((tool) => tool.status === 'Active');

  const agentOptions = activeAgents.map((agent) => ({ label: agent.name, value: agent.id }));
  const providerOptions = activeProviders.map((provider) => ({
    label: `${provider.name} (${provider.model})`,
    value: provider.id,
  }));
  const toolOptions = activeTools.map((tool) => ({ label: tool.name, value: tool.name }));
  const approvalClassOptions = actionClassOptions.filter((option) =>
    (purpose ?? []).includes(option.value),
  );

  function handleFormSubmit(data: FlowNodeFormInput) {
    const agent = activeAgents.find((candidate) => candidate.id === data.agentId);
    const provider = activeProviders.find((candidate) => candidate.id === data.providerId);

    onSubmit({
      agentId: data.agentId,
      agentName: agent?.name ?? t('agentFallback'),
      approvalClasses: data.approvalClasses,
      clientId: initialNode?.clientId ?? crypto.randomUUID(),
      goal: data.goal,
      maxSteps: data.maxSteps,
      spendCapMicros: data.spendCapMicros,
      askPastMicros: data.askPastMicros,
      providerId: data.providerId,
      providerModel: provider?.model ?? '',
      providerName: provider ? `${provider.name} (${provider.model})` : t('providerFallback'),
      purpose: data.purpose,
      toolNames: data.toolNames,
    });
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={initialNode ? t('editTitle') : t('addTitle')}
      description={initialNode ? t('editDescription') : t('addDescription')}
      showCloseButton={false}
      primaryActionLabel={initialNode ? t('save') : t('add')}
      primaryActionType="submit"
      primaryActionForm={addFlowNodeFormId}
    >
      <form
        id={addFlowNodeFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleFormSubmit)}
      >
        <Controller
          control={control}
          name="agentId"
          render={({ field }) => (
            <Select
              label={t('agent')}
              placeholder={t('agentPlaceholder')}
              containerClassName={fieldContainerClassName}
              hint={t('agentHint')}
              className={fieldClassName}
              options={agentOptions}
              value={field.value}
              error={errors.agentId}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          control={control}
          name="providerId"
          render={({ field }) => (
            <Select
              label={t('provider')}
              placeholder={t('providerPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={providerOptions}
              value={field.value}
              error={errors.providerId}
              onChange={field.onChange}
            />
          )}
        />
        <Textarea
          label={t('goal')}
          placeholder={t('goalPlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          rows={3}
          {...register('goal')}
          error={errors.goal}
        />
        <Controller
          control={control}
          name="purpose"
          render={({ field }) => (
            <MultiSelect
              label={t('purpose')}
              placeholder={t('purposePlaceholder')}
              containerClassName={fieldContainerClassName}
              hint={t('purposeHint')}
              options={actionClassOptions}
              value={field.value}
              error={errors.purpose?.message}
              onChange={field.onChange}
            />
          )}
        />
        {approvalClassOptions.length > 0 ? (
          <Controller
            control={control}
            name="approvalClasses"
            render={({ field }) => (
              <MultiSelect
                label={t('approvalFor')}
                placeholder={t('approvalForPlaceholder')}
                containerClassName={fieldContainerClassName}
                options={approvalClassOptions}
                value={field.value}
                onChange={field.onChange}
              />
            )}
          />
        ) : null}
        <Controller
          control={control}
          name="toolNames"
          render={({ field }) => (
            <MultiSelect
              label={t('tools')}
              placeholder={t('toolsPlaceholder')}
              hint={t('toolsHint')}
              containerClassName={fieldContainerClassName}
              options={toolOptions}
              value={field.value}
              onChange={field.onChange}
            />
          )}
        />
        <div className="mb-0">
          <label className="mb-2 block text-xs font-semibold text-white">{t('stepCap')}</label>
          <div className="flex items-center gap-3">
            <RangeSlider
              min={1}
              max={20}
              value={maxSteps}
              onValueChange={(value) => setValue('maxSteps', value, { shouldValidate: true })}
              className="flex-1"
            />
            <span className="w-8 shrink-0 text-right text-sm font-semibold text-white">
              {maxSteps}
            </span>
          </div>
          <p className="mt-2 text-xs text-textGray">{t('stepCapHint')}</p>
        </div>
        <div className="mb-6 grid grid-cols-2 gap-2">
          <Controller
            control={control}
            name="spendCapMicros"
            render={({ field }) => (
              <MoneyInput
                disabled={false}
                label={t('spendCap')}
                onChange={field.onChange}
                placeholder={t('noLimit')}
                value={field.value}
              />
            )}
          />
          <Controller
            control={control}
            name="askPastMicros"
            render={({ field }) => (
              <MoneyInput
                disabled={false}
                label={t('askPast')}
                onChange={field.onChange}
                placeholder={t('neverAsk')}
                value={field.value}
              />
            )}
          />
        </div>
      </form>
    </Modal>
  );
}
