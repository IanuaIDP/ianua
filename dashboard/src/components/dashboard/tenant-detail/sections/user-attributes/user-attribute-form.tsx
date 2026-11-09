'use client';

import { useState } from 'react';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { Textarea } from '@/components/ui/Textarea';
import {
  ATTRIBUTE_NAMESPACES,
  EMPTY_ATTRIBUTE_FORM_VALUES,
  USER_ATTRIBUTE_FORM_ID,
} from '@/constants/user-attribute';
import { useFieldError } from '@/hooks/i18n/use-field-error';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import {
  requiresOptions,
  UserAttributeSchema,
  type UserAttributeInput,
} from '@/schemas/user-attribute-schemas';
import type { UserAttributeKindOption } from '@/types/user-attribute';
import { deriveAttributeKey } from '@/utils/user-attribute';

type UserAttributeFormProps = {
  defaultValues?: UserAttributeInput;
  /** Fixed once declared, so the internal name, kind and owner are read-only here. */
  isEditing?: boolean;
  isSubmitting?: boolean;
  kinds: UserAttributeKindOption[];
  onSubmit: (payload: UserAttributeInput) => void;
};

const dividerClassName = 'border-t border-borderGray';

export function UserAttributeForm({
  defaultValues,
  isEditing = false,
  isSubmitting = false,
  kinds,
  onSubmit,
}: UserAttributeFormProps) {
  const t = useTranslations('dashboard.userFields');
  const tKinds = useLooseTranslations('dashboard.userFields.kinds');
  const tControls = useLooseTranslations('dashboard.userFields.controls');
  const [areAdvancedOpen, setAreAdvancedOpen] = useState(false);
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    setValue,
  } = useForm<UserAttributeInput>({
    resolver: zodResolver(UserAttributeSchema),
    defaultValues: defaultValues ?? EMPTY_ATTRIBUTE_FORM_VALUES,
  });

  const values = useWatch({ control }) as UserAttributeInput;
  const selectedKind = kinds.find((candidate) => candidate.kind === values.kind);

  function handleKindChange(kind: string) {
    setValue('kind', kind, { shouldDirty: true, shouldValidate: Boolean(errors.kind) });
    // The control follows from the kind unless somebody picks another, so
    // changing the kind clears a control the new kind may not render.
    setValue('control', '', { shouldDirty: true });

    const next = kinds.find((candidate) => candidate.kind === kind);

    if (next && !next.sortable) {
      setValue('sortable', false, { shouldDirty: true });
    }
  }

  function handleDisplayNameChange(displayName: string) {
    setValue('displayName', displayName, { shouldDirty: true });

    // The internal name is offered rather than imposed, and only while it is
    // still untouched — and never on an edit, where it cannot change at all.
    if (!isEditing && (!values.key || values.key === deriveAttributeKey(values.displayName))) {
      setValue('key', deriveAttributeKey(displayName), { shouldDirty: true });
    }
  }

  const kindOptions = kinds.map(({ kind }) => ({
    label: tKinds.has(kind) ? tKinds(kind) : kind,
    value: kind,
  }));
  const controlOptions = (selectedKind?.availableControls ?? []).map((candidate) => ({
    label: tControls.has(candidate) ? tControls(candidate) : candidate,
    value: candidate,
  }));
  const showOptions = requiresOptions(values.kind);
  // One textarea holds every choice, so the first problem with any of them is
  // what it shows.
  const optionErrors = errors.options;
  const optionsError =
    optionErrors?.message ??
    (Array.isArray(optionErrors)
      ? optionErrors.find((entry) => entry?.message)?.message
      : undefined);
  const advancedError = useFieldError(errors.key?.message ?? errors.namespace?.message);
  const namespaceOptions = ATTRIBUTE_NAMESPACES.map((namespace) => ({
    label: t(`namespaces.${namespace}`),
    value: namespace,
  }));

  return (
    <form
      id={USER_ATTRIBUTE_FORM_ID}
      className="flex flex-col gap-4"
      onSubmit={handleSubmit(onSubmit)}
    >
      <Select
        label={t('form.fieldType')}
        placeholder={t('form.fieldTypePlaceholder')}
        containerClassName={fieldContainerClassName}
        className={fieldClassName}
        options={kindOptions}
        value={values.kind}
        error={errors.kind}
        disabled={isSubmitting || isEditing}
        onChange={handleKindChange}
      />

      <Select
        label={t('form.shownAs')}
        placeholder={selectedKind ? t('form.shownAsPlaceholder') : t('form.shownAsNoKind')}
        containerClassName={fieldContainerClassName}
        className={fieldClassName}
        options={controlOptions}
        value={values.control || selectedKind?.defaultControl || ''}
        disabled={isSubmitting || controlOptions.length <= 1}
        onChange={(next) => setValue('control', next, { shouldDirty: true })}
      />

      <div className={dividerClassName} />

      <Input
        label={t('form.name')}
        placeholder={t('form.namePlaceholder')}
        containerClassName={fieldContainerClassName}
        className={fieldClassName}
        value={values.displayName}
        error={errors.displayName}
        disabled={isSubmitting}
        onChange={(event) => handleDisplayNameChange(event.target.value)}
      />

      <Input
        label={t('form.helpText')}
        placeholder={t('form.helpTextPlaceholder')}
        containerClassName={fieldContainerClassName}
        className={fieldClassName}
        {...register('description')}
        error={errors.description}
        disabled={isSubmitting}
      />

      {selectedKind?.supportsMaxLength ? (
        <Input
          label={t('form.maxLength')}
          placeholder="200"
          hint={t('form.maxLengthHint')}
          type="number"
          min={1}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('maxLength')}
          error={errors.maxLength}
          disabled={isSubmitting}
        />
      ) : null}

      {selectedKind?.supportsRange ? (
        <div className="flex gap-4">
          <Input
            label={t('form.lowest')}
            type="number"
            containerClassName={`${fieldContainerClassName} flex-1`}
            className={fieldClassName}
            {...register('minimum')}
            error={errors.minimum}
            disabled={isSubmitting}
          />
          <Input
            label={t('form.highest')}
            type="number"
            containerClassName={`${fieldContainerClassName} flex-1`}
            className={fieldClassName}
            {...register('maximum')}
            error={errors.maximum}
            disabled={isSubmitting}
          />
        </div>
      ) : null}

      {showOptions ? (
        <Textarea
          label={t('form.choices')}
          placeholder={t('form.choicesPlaceholder')}
          rows={4}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          value={values.options.join('\n')}
          error={optionsError}
          hint={
            <span className="flex items-center justify-between gap-2">
              <span>{t('form.choicesHint')}</span>
              <span>
                {t('form.optionCount', {
                  count: values.options.filter((option) => option.trim()).length,
                })}
              </span>
            </span>
          }
          disabled={isSubmitting}
          onChange={(event) =>
            setValue('options', event.target.value.split('\n'), { shouldDirty: true })
          }
        />
      ) : null}

      <div className={dividerClassName} />

      <div className="divide-y divide-borderGray rounded-lg border border-borderGray">
        <Switch
          className="px-4 py-3"
          checked={values.required}
          description={t('form.requiredHint')}
          disabled={isSubmitting}
          label={t('form.required')}
          onCheckedChange={(next) => setValue('required', next, { shouldDirty: true })}
        />
        <Switch
          className="px-4 py-3"
          checked={values.listed}
          description={t('form.listedHint')}
          disabled={isSubmitting}
          label={t('form.listed')}
          onCheckedChange={(next) => setValue('listed', next, { shouldDirty: true })}
        />
        <Switch
          className="px-4 py-3"
          checked={values.filterable}
          description={t('form.filterableHint')}
          disabled={isSubmitting}
          label={t('form.filterable')}
          onCheckedChange={(next) => setValue('filterable', next, { shouldDirty: true })}
        />
        <Switch
          className="px-4 py-3"
          checked={values.sortable}
          description={
            selectedKind && !selectedKind.sortable ? t('form.sortableNone') : t('form.sortableHint')
          }
          disabled={isSubmitting || (selectedKind ? !selectedKind.sortable : true)}
          label={t('form.sortable')}
          onCheckedChange={(next) => setValue('sortable', next, { shouldDirty: true })}
        />
        <Switch
          className="px-4 py-3"
          checked={values.sensitive}
          description={t('form.sensitiveHint')}
          disabled={isSubmitting}
          label={t('form.sensitive')}
          onCheckedChange={(next) => setValue('sensitive', next, { shouldDirty: true })}
        />
      </div>

      <div className="rounded-lg border border-borderGray">
        <button
          type="button"
          aria-expanded={areAdvancedOpen}
          className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm font-medium text-white"
          onClick={() => setAreAdvancedOpen(!areAdvancedOpen)}
        >
          <span className="material-symbols-rounded text-lg! text-textGray" aria-hidden="true">
            tune
          </span>
          <span className="flex-1">
            {t('form.advanced')} <span className="text-textGray">{t('form.optional')}</span>
          </span>
          <span className="material-symbols-rounded text-textGray" aria-hidden="true">
            {areAdvancedOpen ? 'arrow_drop_up' : 'arrow_drop_down'}
          </span>
        </button>

        {areAdvancedOpen ? (
          <div className="flex flex-col gap-4 border-t border-borderGray px-4 py-3">
            <Input
              label={t('form.internalName')}
              placeholder="annual_income"
              hint={isEditing ? t('form.internalNameHintEdit') : t('form.internalNameHintNew')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('key')}
              error={errors.key}
              disabled={isSubmitting || isEditing}
            />

            <Controller
              control={control}
              name="namespace"
              render={({ field }) => (
                <Select
                  label={t('form.whoManages')}
                  containerClassName={fieldContainerClassName}
                  className={fieldClassName}
                  options={namespaceOptions}
                  disabled={isSubmitting || isEditing}
                  error={errors.namespace}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />
          </div>
        ) : null}
      </div>

      {!areAdvancedOpen && advancedError ? (
        <p className="text-xs font-medium text-error">{advancedError}</p>
      ) : null}
    </form>
  );
}
