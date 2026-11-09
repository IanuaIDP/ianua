'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation } from '@tanstack/react-query';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select, type SelectOption } from '@/components/ui/Select';
import { useDelegationText } from '@/hooks/dashboard/use-delegation-text';
import { checkAgentAuthorization, getApiErrorMessage } from '@/lib/api';
import {
  CheckAuthorizationSchema,
  type CheckAuthorizationInput,
} from '@/schemas/delegation-schemas';

type CheckAuthorizationModalProps = {
  agentId: string;
  capabilityOptions: SelectOption[];
  open: boolean;
  orgSlug: string;
  tenantSlug: string;
  onClose: () => void;
};

const checkAuthorizationFormId = 'check-authorization-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

const defaultValues: CheckAuthorizationInput = {
  action: '',
  checkMode: 'capability',
  method: '',
  path: '',
};

export function CheckAuthorizationModal({
  agentId,
  capabilityOptions,
  open,
  orgSlug,
  tenantSlug,
  onClose,
}: CheckAuthorizationModalProps) {
  const t = useTranslations('dashboard.delegations.check');
  const { checkMethodOptions, checkModeOptions } = useDelegationText();
  const {
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
  } = useForm<CheckAuthorizationInput>({
    resolver: zodResolver(CheckAuthorizationSchema),
    defaultValues,
  });

  const checkMode = useWatch({ control, name: 'checkMode' });
  const { showNotification } = useNotification();

  const { isPending: isChecking, mutate: runCheck } = useMutation({
    mutationFn: (input: CheckAuthorizationInput) =>
      checkAgentAuthorization(
        orgSlug,
        tenantSlug,
        agentId,
        input.checkMode === 'capability'
          ? { action: input.action ?? '' }
          : { method: input.method ?? '', path: input.path ?? '' },
      ),
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('failed')),
        type: 'error',
      });
    },
    onSuccess: (result) => {
      onClose();
      showNotification({
        message: t('result', {
          decision: result.isAllowed ? t('allowed') : t('denied'),
          reason: result.reason,
        }),
        type: result.isAllowed ? 'success' : 'error',
      });
    },
  });

  useEffect(() => {
    if (!open) {
      reset(defaultValues);
    }
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
      primaryActionForm={checkAuthorizationFormId}
      isPrimaryActionLoading={isChecking}
      isPrimaryActionDisabled={isChecking}
    >
      <form
        id={checkAuthorizationFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((data) => runCheck(data))}
      >
        <Controller
          control={control}
          name="checkMode"
          render={({ field }) => (
            <Select
              label={t('checkBy')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={checkModeOptions}
              value={field.value}
              disabled={isChecking}
              onChange={field.onChange}
            />
          )}
        />

        {checkMode === 'capability' ? (
          <Controller
            control={control}
            name="action"
            render={({ field }) => (
              <Select
                label={t('capability')}
                placeholder={t('capabilityPlaceholder')}
                containerClassName={fieldContainerClassName}
                className={fieldClassName}
                options={capabilityOptions}
                value={field.value ?? ''}
                error={errors.action}
                disabled={isChecking}
                onChange={field.onChange}
              />
            )}
          />
        ) : (
          <div className="grid grid-cols-[auto_1fr] gap-3">
            <Controller
              control={control}
              name="method"
              render={({ field }) => (
                <Select
                  label={t('method')}
                  placeholder={t('method')}
                  containerClassName="mb-0 w-28"
                  className={fieldClassName}
                  options={checkMethodOptions}
                  value={field.value ?? ''}
                  error={errors.method}
                  disabled={isChecking}
                  onChange={field.onChange}
                />
              )}
            />
            <Input
              label={t('requestPath')}
              placeholder="/api/support"
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              {...register('path')}
              error={errors.path}
              disabled={isChecking}
            />
          </div>
        )}
      </form>
    </Modal>
  );
}
