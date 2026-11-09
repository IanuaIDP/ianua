'use client';

import { useState } from 'react';
import type { BaseSyntheticEvent } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Checkbox } from '@/components/ui/Checkbox';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect, type MultiSelectOption } from '@/components/ui/MultiSelect';
import { Select } from '@/components/ui/Select';
import { findDelegationPreset, type DelegationPresetId } from '@/constants/delegation';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import { SigningKeyNotice } from '@/components/dashboard/tenant-detail/sections/agents/delegations/signing-key-notice';
import { GrantDelegationSchema, type GrantDelegationInput } from '@/schemas/delegation-schemas';

type GrantDelegationModalProps = {
  agentName?: string;
  appOptions: MultiSelectOption[];
  capabilityOptions: MultiSelectOption[];
  hasSigningKey?: boolean;
  hasTools?: boolean;
  isLoadingOptions?: boolean;
  isPreparingSigningKey?: boolean;
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onPrepareSigningKey: () => void;
  onSubmit: (data: GrantDelegationInput) => void;
};

const grantDelegationFormId = 'grant-delegation-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

// Standard, not Tight: a default has to be the one most grants actually want,
// or everyone overrides it every time and it has taught them nothing.
const defaultPreset = findDelegationPreset('standard');

const defaultValues: GrantDelegationInput = {
  allowedPaths: '',
  apps: [],
  capabilities: [],
  maxDepth: defaultPreset.maxDepth,
  name: '',
  purpose: '',
  purposeEnforcement: 'enforce',
  requestLimit: defaultPreset.requestLimit,
  requestLimitWindowSeconds: defaultPreset.requestLimitWindowSeconds,
  requiresApproval: defaultPreset.requiresApproval,
  senderConstrained: defaultPreset.senderConstrained,
  task: '',
  thresholdBasisPoints: '2500',
  ttlSeconds: defaultPreset.ttlSeconds,
};

export function GrantDelegationModal({
  agentName,
  appOptions,
  capabilityOptions,
  hasSigningKey = true,
  hasTools = true,
  isLoadingOptions = false,
  isPreparingSigningKey = false,
  isSubmitting = false,
  open,
  onClose,
  onPrepareSigningKey,
  onSubmit,
}: GrantDelegationModalProps) {
  const t = useTranslations('dashboard.delegations.grantModal');
  const {
    budgetWindowOptions,
    depthOptions,
    grantBullets: describeGrantBullets,
    presets,
    ttlOptions,
  } = useDelegationText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<GrantDelegationInput>({
    resolver: zodResolver(GrantDelegationSchema),
    defaultValues,
  });

  const [preset, setPreset] = useState<DelegationPresetId>('standard');
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Cleared on the way out rather than in an effect watching `open`: closing is
  // the event, and the modal calls this however it was dismissed.
  function handleClose() {
    reset(defaultValues);
    setPreset('standard');
    setShowAdvanced(false);
    onClose();
  }

  const purpose = useWatch({ control, name: 'purpose' });
  const maxDepth = useWatch({ control, name: 'maxDepth' });
  const requestLimit = useWatch({ control, name: 'requestLimit' });
  const requiresApproval = useWatch({ control, name: 'requiresApproval' });
  const senderConstrained = useWatch({ control, name: 'senderConstrained' });

  const hasErrors = Object.keys(errors).length > 0;

  // Applying a preset writes the real fields, so More options always shows the
  // truth — a preset is a shortcut to values, never a separate mode.
  function applyPreset(id: DelegationPresetId) {
    const chosen = findDelegationPreset(id);
    setPreset(id);
    setValue('ttlSeconds', chosen.ttlSeconds);
    setValue('maxDepth', chosen.maxDepth);
    setValue('requestLimit', chosen.requestLimit);
    setValue('requestLimitWindowSeconds', chosen.requestLimitWindowSeconds);
    setValue('requiresApproval', chosen.requiresApproval);
    setValue('senderConstrained', chosen.senderConstrained);
  }

  function handleInvalidSubmit(_errors: unknown, event?: BaseSyntheticEvent) {
    const formElement = event?.target as HTMLFormElement | undefined;
    formElement?.scrollTo({ behavior: 'smooth', top: 0 });
  }

  const grantBullets = describeGrantBullets({
    maxDepth,
    purpose,
    requestLimit,
    requiresApproval: Boolean(requiresApproval),
    senderConstrained: Boolean(senderConstrained),
  });

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description', { name: agentName ?? t('agentFallback') })}
      showCloseButton={false}
      size="lg"
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={grantDelegationFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={grantDelegationFormId}
        className="flex flex-col gap-5"
        onSubmit={handleSubmit(onSubmit, handleInvalidSubmit)}
      >
        {hasErrors ? (
          <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
            {t('fixFields')}
          </p>
        ) : null}

        {hasSigningKey ? null : (
          <SigningKeyNotice isPreparing={isPreparingSigningKey} onPrepare={onPrepareSigningKey} />
        )}

        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-white">{t('capabilities')}</p>
          <Controller
            control={control}
            name="capabilities"
            render={({ field }) => (
              <MultiSelect
                placeholder={isLoadingOptions ? t('loading') : t('capabilitiesPlaceholder')}
                hint={
                  hasTools || isLoadingOptions
                    ? t('capabilitiesHint')
                    : t('capabilitiesHintNoTools')
                }
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={capabilityOptions}
                value={field.value}
                error={errors.capabilities?.message}
                disabled={isSubmitting || isLoadingOptions}
                onChange={field.onChange}
              />
            )}
          />
        </div>

        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-white">{t('apps')}</p>
          <Controller
            control={control}
            name="apps"
            render={({ field }) => (
              <MultiSelect
                placeholder={appOptions.length ? t('appsPlaceholder') : t('appsNone')}
                hint={t('appsHint')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={appOptions}
                value={field.value}
                error={errors.apps?.message}
                disabled={isSubmitting || !appOptions.length}
                onChange={field.onChange}
              />
            )}
          />
        </div>

        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-white">{t('accessLevel')}</p>
          <div className="grid gap-2 sm:grid-cols-3">
            {presets.map((option) => {
              const isSelected = preset === option.id;

              return (
                <button
                  key={option.id}
                  type="button"
                  disabled={isSubmitting}
                  aria-pressed={isSelected}
                  onClick={() => applyPreset(option.id)}
                  className={`flex flex-col rounded-lg border px-2 py-3 text-left transition-colors ${
                    isSelected
                      ? 'border-primary/30 bg-primary/10 '
                      : 'border-borderGray bg-transparent hover:bg-borderGray'
                  }`}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-white">{option.label}</span>
                    <span
                      className={`flex size-3.5 shrink-0 items-center justify-center rounded-full border-2 border-primary transition-colors ${
                        isSelected ? 'bg-cardBg' : 'bg-transparent'
                      }`}
                    >
                      {isSelected ? <span className="size-1.5 rounded-full bg-primary" /> : null}
                    </span>
                  </span>
                  <span className="mt-1 block text-[10px] leading-snug text-textGray">
                    {option.description}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="rounded-lg border border-borderGray bg-surfaceChip px-2.5 py-2">
          <div className="flex items-center gap-1.5">
            <span className="material-symbols-rounded text-sm! text-white" aria-hidden>
              info
            </span>
            <p className="text-xs font-medium text-white">{t('summary')}</p>
          </div>
          <ul className="list-disc pl-8 text-[10px] leading-relaxed text-white marker:text-white">
            {grantBullets.map((bullet) => (
              <li key={bullet}>{bullet}</li>
            ))}
          </ul>
        </div>

        <div className="rounded-lg border border-borderGray">
          <button
            type="button"
            className={`flex w-full items-center justify-between gap-2 px-3 py-2.5 text-left transition hover:bg-hoverBg ${
              showAdvanced ? 'border-b border-borderGray' : ''
            }`}
            onClick={() => setShowAdvanced((previous) => !previous)}
          >
            <span className="flex items-center gap-2">
              <span className="material-symbols-rounded text-textGray" aria-hidden>
                tune
              </span>
              <span className="text-xs font-semibold text-white">
                {t('advanced')} <span className="font-normal text-textGray">{t('optional')}</span>
              </span>
            </span>
            <span className="material-symbols-rounded text-textGray" aria-hidden>
              {showAdvanced ? 'expand_less' : 'expand_more'}
            </span>
          </button>

          {showAdvanced ? (
            <div className="flex flex-col gap-4 p-3">
              <Input
                label={t('purpose')}
                placeholder={t('purposePlaceholder')}
                hint={t('purposeHint')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('purpose')}
                error={errors.purpose}
                disabled={isSubmitting}
              />

              <Input
                label={t('name')}
                placeholder={t('namePlaceholder')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('name')}
                error={errors.name}
                disabled={isSubmitting}
              />

              <Controller
                control={control}
                name="ttlSeconds"
                render={({ field }) => (
                  <Select
                    label={t('expires')}
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    options={ttlOptions}
                    value={field.value}
                    error={errors.ttlSeconds}
                    disabled={isSubmitting}
                    onChange={field.onChange}
                  />
                )}
              />

              <Controller
                control={control}
                name="maxDepth"
                render={({ field }) => (
                  <Select
                    label={t('depth')}
                    hint={t('depthHint')}
                    containerClassName={fieldContainerClassName}
                    className={fieldClassName}
                    options={depthOptions}
                    value={field.value}
                    error={errors.maxDepth}
                    disabled={isSubmitting}
                    onChange={field.onChange}
                  />
                )}
              />

              <div className="grid grid-cols-[1fr_auto] gap-3">
                <Input
                  label={t('requestLimit')}
                  placeholder={t('noLimit')}
                  inputMode="numeric"
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  {...register('requestLimit')}
                  error={errors.requestLimit}
                  disabled={isSubmitting}
                />
                <Controller
                  control={control}
                  name="requestLimitWindowSeconds"
                  render={({ field }) => (
                    <Select
                      label={t('per')}
                      containerClassName="mb-0 w-32"
                      className={fieldClassName}
                      options={budgetWindowOptions}
                      value={field.value}
                      disabled={isSubmitting}
                      onChange={field.onChange}
                    />
                  )}
                />
              </div>

              <Input
                label={t('paths')}
                placeholder="/api/ledger/*"
                hint={t('pathsHint')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('allowedPaths')}
                error={errors.allowedPaths}
                disabled={isSubmitting}
              />

              <Input
                label={t('task')}
                placeholder="invoice-triage"
                maxLength={500}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                {...register('task')}
                error={errors.task}
                disabled={isSubmitting}
              />

              <div className="flex flex-col gap-3">
                <Checkbox
                  label={
                    <span>
                      <span className="block">{t('senderConstrained')}</span>
                      <span className="block mt-1 font-normal text-textGray">
                        {t('senderConstrainedHint')}
                      </span>
                    </span>
                  }
                  {...register('senderConstrained')}
                  disabled={isSubmitting}
                />
                <Checkbox
                  label={
                    <span>
                      <span className="block">{t('requiresApproval')}</span>
                      <span className="block mt-1 font-normal text-textGray">
                        {t('requiresApprovalHint')}
                      </span>
                    </span>
                  }
                  {...register('requiresApproval')}
                  disabled={isSubmitting}
                />
              </div>
            </div>
          ) : null}
        </div>
      </form>
    </Modal>
  );
}
