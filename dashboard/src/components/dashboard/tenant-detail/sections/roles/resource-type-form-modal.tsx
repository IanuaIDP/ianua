'use client';

import { useState } from 'react';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { DATA_CLASS_LEVEL_ORDER } from '@/constants/classification';
import { useValidationText } from '@/hooks/i18n/use-field-error';
import { ResourceTypeSchema, type ResourceTypeInput } from '@/schemas/resource-type-schemas';
import { cn } from '@/utils/cn';

type ResourceTypeFormModalProps = {
  defaultValues?: ResourceTypeInput;
  description: string;
  isKeyLocked?: boolean;
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: ResourceTypeInput) => void;
  open: boolean;
  primaryActionLabel: string;
  title: string;
};

const emptyFormValues: ResourceTypeInput = {
  actions: [{ displayName: 'Read', implies: [], key: 'read' }],
  dataClass: 'Internal',
  description: '',
  displayName: '',
  key: '',
};

const resourceTypeFormId = 'resource-type-form';

function toResourceKey(name: string) {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

export function ResourceTypeFormModal({
  defaultValues,
  description,
  isKeyLocked = false,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  primaryActionLabel,
  title,
}: ResourceTypeFormModalProps) {
  const t = useTranslations('dashboard.resources.form');
  const tStatus = useTranslations('dashboard.status');
  const validationText = useValidationText();
  const [wasOpen, setWasOpen] = useState(open);
  const [isKeyTyped, setIsKeyTyped] = useState(false);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<ResourceTypeInput>({
    resolver: zodResolver(ResourceTypeSchema),
    defaultValues: defaultValues ?? emptyFormValues,
  });
  const actions = useWatch({ control, name: 'actions' }) ?? [];

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      setIsKeyTyped(false);
      reset(defaultValues ?? emptyFormValues);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    onClose();
  }

  function updateAction(index: number, field: 'displayName' | 'key', value: string) {
    setValue(
      'actions',
      actions.map((action, current) =>
        current === index ? { ...action, [field]: value } : action,
      ),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  function toggleImplies(index: number, key: string) {
    setValue(
      'actions',
      actions.map((action, current) => {
        if (current !== index) {
          return action;
        }

        const implies = action.implies.includes(key)
          ? action.implies.filter((entry) => entry !== key)
          : [...action.implies, key];

        return { ...action, implies };
      }),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  function addAction() {
    setValue('actions', [...actions, { displayName: '', implies: [], key: '' }], {
      shouldDirty: true,
      shouldValidate: true,
    });
  }

  function removeAction(index: number) {
    const removed = actions[index]?.key;

    setValue(
      'actions',
      actions
        .filter((_, current) => current !== index)
        .map((action) => ({
          ...action,
          implies: action.implies.filter((entry) => entry !== removed),
        })),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      showCloseButton={false}
      primaryActionLabel={primaryActionLabel}
      primaryActionType="submit"
      primaryActionForm={resourceTypeFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
      size="lg"
    >
      <form
        id={resourceTypeFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Input
            label={t('name')}
            placeholder={t('namePlaceholder')}
            containerClassName="mb-0"
            className="bg-cardBg"
            {...register('displayName', {
              onChange: (event) => {
                if (!isKeyLocked && !isKeyTyped) {
                  setValue('key', toResourceKey(event.target.value), { shouldDirty: true });
                }
              },
            })}
            error={errors.displayName}
            disabled={isSubmitting}
          />
          <Input
            label={t('key')}
            placeholder="project"
            hint={isKeyLocked ? t('keyLockedHint') : t('keyHint')}
            containerClassName="mb-0"
            className="bg-cardBg"
            {...register('key', { onChange: () => setIsKeyTyped(true) })}
            error={errors.key}
            disabled={isSubmitting || isKeyLocked}
          />
        </div>

        <Controller
          control={control}
          name="dataClass"
          render={({ field }) => (
            <Select
              label={t('dataClass')}
              hint={t('dataClassHint')}
              containerClassName="mb-0"
              className="bg-cardBg"
              options={DATA_CLASS_LEVEL_ORDER.map((level) => ({
                label: tStatus(level),
                value: level,
              }))}
              value={field.value}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />

        <Input
          label={t('descriptionLabel')}
          placeholder={t('descriptionPlaceholder')}
          containerClassName="mb-0"
          className="bg-cardBg"
          {...register('description')}
          error={errors.description}
          disabled={isSubmitting}
        />

        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-semibold text-white">{t('actions')}</span>
            <button
              type="button"
              disabled={isSubmitting}
              onClick={addAction}
              className="text-xs font-semibold text-focus transition hover:text-focus/80 disabled:pointer-events-none disabled:opacity-60"
            >
              {t('addAction')}
            </button>
          </div>
          <p className="mb-2 text-xs text-textGray">{t('actionsHint')}</p>

          <div className="rounded-lg border border-borderGray">
            {actions.map((action, index) => (
              <div
                key={index}
                className={cn('px-3 py-2.5', index > 0 && 'border-t border-borderGray')}
              >
                <div className="flex items-start gap-2">
                  <Input
                    placeholder={t('actionNamePlaceholder')}
                    containerClassName="mb-0 flex-1"
                    className="bg-cardBg"
                    value={action.displayName}
                    error={errors.actions?.[index]?.displayName}
                    disabled={isSubmitting}
                    onChange={(event) => updateAction(index, 'displayName', event.target.value)}
                  />
                  <Input
                    placeholder="write"
                    containerClassName="mb-0 flex-1"
                    className="bg-cardBg"
                    value={action.key}
                    error={errors.actions?.[index]?.key}
                    disabled={isSubmitting}
                    onChange={(event) => updateAction(index, 'key', event.target.value)}
                  />
                  <button
                    type="button"
                    disabled={isSubmitting || actions.length === 1}
                    onClick={() => removeAction(index)}
                    aria-label={t('removeAction')}
                    className="mt-1 text-textGray transition hover:text-white disabled:pointer-events-none disabled:opacity-60"
                  >
                    <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                      close
                    </span>
                  </button>
                </div>

                {actions.length > 1 ? (
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-textGray">{t('alsoGrants')}</span>
                    {actions
                      .filter((other, current) => current !== index && other.key)
                      .map((other) => {
                        const selected = action.implies.includes(other.key);

                        return (
                          <button
                            key={other.key}
                            type="button"
                            disabled={isSubmitting}
                            onClick={() => toggleImplies(index, other.key)}
                            className={cn(
                              'rounded-full border px-2.5 py-1 text-xs font-medium transition disabled:pointer-events-none disabled:opacity-60',
                              selected
                                ? 'border-transparent bg-primary/15 text-primary'
                                : 'border-borderGray bg-surfaceRaised text-textGray hover:border-white/20 hover:text-white',
                            )}
                          >
                            {other.displayName || other.key}
                          </button>
                        );
                      })}
                  </div>
                ) : null}

                {errors.actions?.[index]?.implies?.message ? (
                  <p className="mt-2 text-xs text-error">
                    {validationText(errors.actions[index]?.implies?.message)}
                  </p>
                ) : null}
              </div>
            ))}
          </div>

          {errors.actions?.message ? (
            <p className="mt-2 text-xs text-error">{validationText(errors.actions.message)}</p>
          ) : null}
        </div>
      </form>
    </Modal>
  );
}
