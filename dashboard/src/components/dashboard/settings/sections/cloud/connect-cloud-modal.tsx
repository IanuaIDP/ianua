'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { CloudCredentialFields } from '@/components/dashboard/settings/sections/cloud/cloud-credential-fields';
import { Select } from '@/components/ui/Select';
import { Modal } from '@/components/ui/modal';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { Tooltip } from '@/components/ui/tooltip';
import { CLOUD_PROVIDER_OPTIONS, EMPTY_CLOUD_CREDENTIALS } from '@/constants/cloud';
import { beginCloudConnection, getApiErrorMessage } from '@/lib/api';
import { CloudCredentialSchema, type CloudCredentialInput } from '@/schemas/cloud-schemas';
import type { CloudProviderId } from '@/types/cloud-account';

type ConnectCloudModalProps = {
  connectedProviders: CloudProviderId[];
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (provider: CloudProviderId, payload: CloudCredentialInput) => void;
  open: boolean;
  orgSlug?: string;
};

const connectCloudFormId = 'connect-cloud-form';

export function ConnectCloudModal({
  connectedProviders,
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
}: ConnectCloudModalProps) {
  const t = useTranslations('dashboard.settings.cloud');
  const copy = useCopyToClipboard();
  const [prevOpen, setPrevOpen] = useState(open);
  const [provider, setProvider] = useState<CloudProviderId>('aws');
  const {
    formState: { errors, isDirty },
    handleSubmit,
    register,
    reset,
  } = useForm<CloudCredentialInput>({
    resolver: zodResolver(CloudCredentialSchema),
    defaultValues: EMPTY_CLOUD_CREDENTIALS.aws,
    mode: 'onBlur',
  });

  const {
    data: instructions,
    error: instructionsError,
    isLoading: isLoadingInstructions,
  } = useQuery({
    enabled: open && Boolean(orgSlug),
    queryFn: () => beginCloudConnection(orgSlug ?? '', provider),
    queryKey: ['cloud-connection-instructions', orgSlug, provider],
    staleTime: Infinity,
  });

  if (open !== prevOpen) {
    setPrevOpen(open);

    if (open) {
      setProvider('aws');
      reset(EMPTY_CLOUD_CREDENTIALS.aws);
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    reset(EMPTY_CLOUD_CREDENTIALS.aws);
    onClose();
  }

  function handleProviderChange(value: string) {
    const next = value as CloudProviderId;

    setProvider(next);
    reset(EMPTY_CLOUD_CREDENTIALS[next]);
  }

  async function copyExternalId() {
    await copy(instructions?.externalId ?? '', t('modal.copied'));
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      autoFocus={false}
      title={t('modal.title')}
      description={t('modal.description')}
      primaryActionLabel={t('modal.submit')}
      primaryActionType="submit"
      primaryActionForm={connectCloudFormId}
      isPrimaryActionDisabled={!isDirty || isSubmitting || isLoadingInstructions}
      isPrimaryActionLoading={isSubmitting}
      onSecondaryAction={handleClose}
      showCloseButton={false}
      size="lg"
    >
      <form
        id={connectCloudFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((payload) => onSubmit(provider, payload))}
      >
        <Select
          label={t('modal.provider')}
          containerClassName="mb-0"
          disabled={isSubmitting}
          onChange={handleProviderChange}
          options={CLOUD_PROVIDER_OPTIONS}
          value={provider}
          hint={
            connectedProviders.includes(provider)
              ? t('modal.reconnectHint')
              : t(`providers.${provider}.grant`)
          }
        />

        {instructionsError ? (
          <p className="text-xs font-medium text-error">
            {getApiErrorMessage(instructionsError, t('modal.stepsFailed'))}
          </p>
        ) : null}

        {instructions && instructions.steps.length > 0 ? (
          <div className="flex flex-col rounded-lg border border-borderGray py-3">
            {instructions.steps.map((step, index) => {
              const lastIndex = instructions.steps.length - 1;
              const showConsoleLink = index === 0 && Boolean(instructions.consoleUrl);
              const showExternalId =
                index === Math.min(1, lastIndex) && Boolean(instructions.externalId);
              const showCredentialFields = index === lastIndex;

              return (
                <div
                  key={step}
                  className="flex gap-2.5 border-b border-borderGray px-4 pb-4 pt-4 first:pt-0 last:border-b-0 last:pb-0"
                >
                  <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[10px] font-medium text-primary">
                    {index + 1}
                  </span>
                  <div className="flex min-w-0 flex-1 flex-col gap-2 pt-0.5">
                    <p className="text-xs font-medium text-white">{step}</p>

                    {showConsoleLink ? (
                      <a
                        href={instructions.consoleUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex w-fit items-center gap-1 text-xs font-medium text-primary transition hover:text-primary/80"
                      >
                        {t('modal.openConsole')}
                        <span className="material-symbols-rounded text-sm!">open_in_new</span>
                      </a>
                    ) : null}

                    {showExternalId ? (
                      <div className="flex items-center justify-between gap-4 bg-transparent border border-borderGray rounded-md px-3 py-2">
                        <div className="min-w-0">
                          <p className="text-[10px] font-medium text-textGray">
                            {t('modal.externalId')}
                          </p>
                          <p className="mt-0.5 break-all text-xs font-semibold text-white">
                            {instructions.externalId}
                          </p>
                        </div>
                        <Tooltip content={t('modal.copyExternalId')} side="top-left">
                          <button
                            type="button"
                            aria-label={t('modal.copyExternalId')}
                            onClick={(event) => {
                              event.currentTarget.blur();
                              void copyExternalId();
                            }}
                            className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-white"
                          >
                            <span className="material-symbols-rounded">content_copy</span>
                          </button>
                        </Tooltip>
                      </div>
                    ) : null}

                    {showCredentialFields ? (
                      <CloudCredentialFields
                        disabled={isSubmitting}
                        errors={errors}
                        provider={provider}
                        register={register}
                      />
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <CloudCredentialFields
            disabled={isSubmitting}
            errors={errors}
            provider={provider}
            register={register}
          />
        )}
      </form>
    </Modal>
  );
}
