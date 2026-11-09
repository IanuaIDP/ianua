'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Checkbox } from '@/components/ui/Checkbox';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { TagInput } from '@/components/ui/TagInput';
import { useCredentialText } from '@/hooks/dashboard/use-credential-text';
import { useValidationText } from '@/hooks/i18n/use-field-error';
import {
  EditAttestationPolicySchema,
  type EditAttestationPolicyInput,
} from '@/schemas/credential-schemas';
import type { AttestationMethod } from '@/types/credential';

type EditAttestationPolicyModalProps = {
  defaultValues: EditAttestationPolicyInput;
  isSubmitting?: boolean;
  open: boolean;
  onClose: () => void;
  onSubmit: (data: EditAttestationPolicyInput) => void;
};

const editAttestationPolicyFormId = 'edit-attestation-policy-form';

export function EditAttestationPolicyModal({
  defaultValues,
  isSubmitting = false,
  open,
  onClose,
  onSubmit,
}: EditAttestationPolicyModalProps) {
  const t = useTranslations('dashboard.credentials.policyModal');
  const validationText = useValidationText();
  const { attestationMethodOptions, reattestIntervalOptions } = useCredentialText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    reset,
  } = useForm<EditAttestationPolicyInput>({
    resolver: zodResolver(EditAttestationPolicySchema),
    defaultValues,
  });

  useEffect(() => {
    if (open) {
      reset(defaultValues);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, reset]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={editAttestationPolicyFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={editAttestationPolicyFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Controller
          control={control}
          name="methods"
          render={({ field }) => (
            <div>
              <p className="mb-2 text-xs font-semibold text-white">{t('trustedMethod')}</p>
              <div className="flex flex-col gap-2">
                {attestationMethodOptions.map((method) => {
                  const isChecked = field.value.includes(method.value);

                  function toggle() {
                    if (isSubmitting) {
                      return;
                    }

                    const next: AttestationMethod[] = isChecked
                      ? field.value.filter((value) => value !== method.value)
                      : [...field.value, method.value];

                    field.onChange(next);
                  }

                  return (
                    <div
                      key={method.value}
                      className="flex items-center justify-between gap-3 rounded-lg border border-borderGray px-3 py-2.5"
                    >
                      <Checkbox
                        checked={isChecked}
                        containerClassName="mb-0"
                        disabled={isSubmitting}
                        label={method.label}
                        onChange={toggle}
                      />
                      <span className="inline-flex items-center gap-1 text-[10px] text-textGray">
                        {t('sentAs')}
                        <code className="rounded-md bg-white/10 px-1.5 py-0.5 font-mono text-[10px] text-white">
                          {method.value}
                        </code>
                      </span>
                    </div>
                  );
                })}
              </div>
              {errors.methods ? (
                <p className="mt-2 text-xs text-error">{validationText(errors.methods.message)}</p>
              ) : (
                <p className="mt-2 text-[10px] text-textGray">{t('methodsHint')}</p>
              )}
            </div>
          )}
        />

        <Controller
          control={control}
          name="reattestIntervalSeconds"
          render={({ field }) => (
            <Select
              label={t('reattestEvery')}
              containerClassName="mb-0"
              className="bg-cardBg"
              hint={t('reattestHint')}
              options={reattestIntervalOptions}
              value={field.value}
              error={errors.reattestIntervalSeconds}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />

        <Controller
          control={control}
          name="allowedOrigins"
          render={({ field }) => (
            <TagInput
              label={t('origins')}
              containerClassName="mb-0"
              placeholder="spiffe://cluster/ns/agents"
              hint={t('originsHint', {
                example:
                  'aws:<account>, gcp:<project>, spiffe://<trust domain>/<path>, tpm:aik:<fingerprint>',
              })}
              value={field.value}
              error={errors.allowedOrigins?.message}
              disabled={isSubmitting}
              onChange={field.onChange}
            />
          )}
        />
      </form>
    </Modal>
  );
}
