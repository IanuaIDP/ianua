'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import Link from 'next/link';
import { Controller, useForm } from 'react-hook-form';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { TagInput } from '@/components/ui/TagInput';
import { Textarea } from '@/components/ui/Textarea';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, getTenantModelProviders, writeSandboxCode } from '@/lib/api';
import { WriteCodeSchema, type WriteCodeFormInput } from '@/schemas/sandbox-schemas';
import type { WrittenSandboxCode } from '@/types/sandbox';
import { getTenantScopedPath } from '@/utils/dashboard-routes';

type WriteCodeModalProps = {
  /** Code that failed when tried, for the model to fix instead of writing afresh. */
  fix?: { code: string; failure: string } | null;
  onClose: () => void;
  onWritten: (written: WrittenSandboxCode) => void;
  open: boolean;
  packages: string[];
  sandboxId: string;
};

const formId = 'write-code-form';

/** Asks the tenant's model to write code from words, or to fix what failed. Saves nothing. */
export function WriteCodeModal({
  fix = null,
  onClose,
  onWritten,
  open,
  packages,
  sandboxId,
}: WriteCodeModalProps) {
  const t = useTranslations('dashboard.sandboxes.writeCode');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { showNotification } = useNotification();
  const [wasOpen, setWasOpen] = useState(open);
  const defaults: WriteCodeFormInput = {
    inputs: [],
    providerId: '',
    words: fix ? t('fixWords') : '',
  };
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<WriteCodeFormInput>({
    defaultValues: defaults,
    resolver: zodResolver(WriteCodeSchema),
  });
  const { data: providers, isLoading } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
    retry: false,
  });
  const activeProviders = (providers ?? []).filter((provider) => provider.status === 'Active');
  const { isPending, mutate } = useMutation({
    mutationFn: (values: WriteCodeFormInput) =>
      writeSandboxCode(orgSlug ?? '', tenantSlug, sandboxId, {
        fix,
        inputs: values.inputs,
        packages,
        providerId: values.providerId,
        words: values.words,
      }),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: (written) => {
      onWritten(written);
    },
  });

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      reset(defaults);
    }
  }

  return (
    <Modal
      description={fix ? t('fixDescription') : t('description')}
      isPrimaryActionDisabled={isPending || (!isLoading && activeProviders.length === 0)}
      isPrimaryActionLoading={isPending}
      onClose={onClose}
      open={open}
      primaryActionForm={formId}
      primaryActionLabel={fix ? t('fixSubmit') : t('submit')}
      primaryActionType="submit"
      showCloseButton={false}
      title={fix ? t('fixTitle') : t('title')}
    >
      <form
        id={formId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((values) => mutate(values))}
      >
        {!isLoading && activeProviders.length === 0 ? (
          <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs text-textGray">
            {t.rich('noProvider', {
              link: (chunks) => (
                <Link
                  className="font-semibold text-primary hover:underline"
                  href={getTenantScopedPath(
                    isTenantView,
                    orgSlug,
                    tenantSlug,
                    'model-providers',
                    'model-providers',
                  )}
                >
                  {chunks}
                </Link>
              ),
            })}
          </p>
        ) : null}
        <Controller
          control={control}
          name="providerId"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isPending}
              error={errors.providerId}
              label={t('provider')}
              onChange={field.onChange}
              options={activeProviders.map((provider) => ({
                label: provider.name,
                value: provider.id,
              }))}
              placeholder={t('pickProvider')}
              value={field.value}
            />
          )}
        />
        <Textarea
          {...register('words')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          disabled={isPending}
          error={errors.words}
          hint={t('wordsHint')}
          label={t('words')}
          maxLength={500}
        />
        {!fix ? (
          <Controller
            control={control}
            name="inputs"
            render={({ field }) => (
              <TagInput
                containerClassName={fieldContainerClassName}
                disabled={isPending}
                hint={t('inputsHint')}
                label={t('inputs')}
                onChange={field.onChange}
                value={field.value}
              />
            )}
          />
        ) : null}
      </form>
    </Modal>
  );
}
