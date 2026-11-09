'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { changeWorkflowRisk, getApiErrorMessage, raiseWorkflowRisk } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  RaiseRiskSchema,
  RISK_EFFECTS,
  type RaiseRiskFormInput,
} from '@/schemas/workflow-risk-schemas';
import type { WorkflowRisk } from '@/types/workflow-risk';
import type { WorkflowIntegration, WorkflowOperation } from '@/types/workflows';

type RaiseRiskModalProps = {
  integrations: WorkflowIntegration[];
  onClose: () => void;
  operations: WorkflowOperation[];
  /** The risk being changed; `null` raises a new one. */
  risk: WorkflowRisk | null;
  risks: WorkflowRisk[];
};

const formId = 'raise-risk-form';

function effectOf(risk: WorkflowRisk | null): RaiseRiskFormInput['effect'] {
  return RISK_EFFECTS.find((effect) => effect === risk?.effect) ?? 'undeclared';
}

/** Raises or changes what one step of an integration counts as. */
export function RaiseRiskModal({
  integrations,
  onClose,
  operations,
  risk,
  risks,
}: RaiseRiskModalProps) {
  const t = useTranslations('dashboard.workflowRisks.modal');
  const tEffect = useTranslations('dashboard.workflowRisks.effects');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const {
    control,
    formState: { errors },
    handleSubmit,
    setValue,
  } = useForm<RaiseRiskFormInput>({
    defaultValues: {
      effect: effectOf(risk),
      integration: risk?.integration ?? '',
      operation: risk?.operation ?? '',
    },
    resolver: zodResolver(RaiseRiskSchema),
  });
  const integration = useWatch({ control, name: 'integration' });
  const operation = useWatch({ control, name: 'operation' });
  const raised = risks.find(
    (candidate) => candidate.integration === integration && candidate.operation === operation,
  );
  const target = risk ?? raised ?? null;
  const operationOptions = operations
    .filter((item) => item.integration === integration)
    .map((item) => ({ label: item.title, value: item.operation }));
  const { isPending, mutate } = useMutation({
    mutationFn: (values: RaiseRiskFormInput) =>
      target
        ? changeWorkflowRisk(orgSlug ?? '', tenantSlug, target.id, values.effect)
        : raiseWorkflowRisk(orgSlug ?? '', tenantSlug, values),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async () => {
      showNotification({ message: target ? t('changed') : t('raised'), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['workflow-risks', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onClose();
    },
  });

  return (
    <Modal
      open
      description={t('description')}
      isPrimaryActionDisabled={isPending}
      isPrimaryActionLoading={isPending}
      onClose={onClose}
      primaryActionForm={formId}
      primaryActionLabel={target ? t('submitChange') : t('submitRaise')}
      primaryActionType="submit"
      showCloseButton={false}
      title={target ? t('titleChange') : t('titleRaise')}
    >
      <form
        id={formId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit((values) => mutate(values))}
      >
        <Controller
          control={control}
          name="integration"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isPending || Boolean(risk)}
              error={errors.integration}
              label={t('integration')}
              onChange={(value) => {
                field.onChange(value);
                setValue('operation', '');
              }}
              options={integrations.map((item) => ({ label: item.title, value: item.key }))}
              placeholder={t('pickIntegration')}
              value={field.value}
            />
          )}
        />
        <Controller
          control={control}
          name="operation"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isPending || Boolean(risk) || !integration}
              error={errors.operation}
              label={t('operation')}
              onChange={field.onChange}
              options={operationOptions}
              placeholder={t('pickOperation')}
              value={field.value}
            />
          )}
        />
        <Controller
          control={control}
          name="effect"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              disabled={isPending}
              label={t('effect')}
              onChange={field.onChange}
              options={RISK_EFFECTS.map((effect) => ({ label: tEffect(effect), value: effect }))}
              value={field.value}
            />
          )}
        />
        {raised && !risk ? <p className="text-xs text-textGray">{t('alreadyRaised')}</p> : null}
        <p className="rounded-lg bg-orange/10 px-3 py-2 text-xs text-orange">{t('warning')}</p>
      </form>
    </Modal>
  );
}
