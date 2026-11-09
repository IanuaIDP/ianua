'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { RangeSlider } from '@/components/ui/RangeSlider';
import { Select } from '@/components/ui/Select';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import { useToolOptions } from '@/hooks/dashboard/use-tool-options';
import type { StartAgentRunPayload } from '@/lib/api/services/runs';
import { StartRunFormSchema, type StartRunFormInput } from '@/schemas/run-schemas';
import type { Delegation } from '@/types/delegation';
import type { ModelProvider } from '@/types/model-provider';

type StartRunModalProps = {
  delegations: Delegation[];
  isSubmitting?: boolean;
  open: boolean;
  providers: ModelProvider[];
  onClose: () => void;
  onSubmit: (payload: StartAgentRunPayload) => void;
};

const startRunFormId = 'start-run-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: StartRunFormInput = {
  approvalClasses: [],
  delegationId: '',
  goal: '',
  maxSteps: 8,
  providerId: '',
  purpose: [],
};

export function StartRunModal({
  delegations,
  isSubmitting = false,
  open,
  providers,
  onClose,
  onSubmit,
}: StartRunModalProps) {
  const t = useTranslations('dashboard.agents.runs.startModal');
  const { actionClassOptions } = useToolOptions();
  const { title: delegationTitle } = useDelegationText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<StartRunFormInput>({
    resolver: zodResolver(StartRunFormSchema),
    defaultValues,
  });

  useEffect(() => {
    if (open) {
      reset(defaultValues);
    }
  }, [open, reset]);

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

  const activeProviders = providers.filter((provider) => provider.status === 'Active');
  const activeDelegations = delegations.filter((delegation) => delegation.status === 'Active');

  const providerOptions = activeProviders.map((provider) => ({
    label: `${provider.name} (${provider.model})`,
    value: provider.id,
  }));
  const delegationOptions = [
    { label: t('none'), value: '' },
    ...activeDelegations.map((delegation) => ({
      label: delegationTitle(delegation),
      value: delegation.delegationId,
    })),
  ];
  const approvalClassOptions = actionClassOptions.filter((option) =>
    (purpose ?? []).includes(option.value),
  );

  function handleFormSubmit(data: StartRunFormInput) {
    onSubmit({
      approvalClasses: data.approvalClasses,
      delegationId: data.delegationId || null,
      goal: data.goal,
      maxSteps: data.maxSteps,
      providerId: data.providerId,
      purpose: data.purpose,
    });
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={startRunFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={startRunFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleFormSubmit)}
      >
        <Input
          label={t('goal')}
          placeholder={t('goalPlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('goal')}
          error={errors.goal}
          disabled={isSubmitting}
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
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
        <Controller
          control={control}
          name="delegationId"
          render={({ field }) => (
            <Select
              label={t('delegation')}
              hint={t('delegationHint')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={delegationOptions}
              value={field.value}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
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
              disabled={isSubmitting}
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
                disabled={isSubmitting}
                onChange={field.onChange}
              />
            )}
          />
        ) : null}
        <div className="mb-0">
          <label className="mb-2 block text-xs font-semibold text-white">{t('stepLimit')}</label>
          <div className="flex items-center gap-3">
            <RangeSlider
              min={1}
              max={20}
              value={maxSteps}
              disabled={isSubmitting}
              onValueChange={(value) => setValue('maxSteps', value, { shouldValidate: true })}
              className="flex-1"
            />
            <span className="w-8 shrink-0 text-right text-sm font-semibold text-white">
              {maxSteps}
            </span>
          </div>
          <p className="mt-2 text-xs text-textGray">{t('stepLimitHint')}</p>
        </div>
      </form>
    </Modal>
  );
}
