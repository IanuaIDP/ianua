'use client';

import { Controller, type Control, type FormState, type UseFormRegister } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { TagInput } from '@/components/ui/TagInput';
import { Textarea } from '@/components/ui/Textarea';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getTenantAgents, getTenantModelProviders } from '@/lib/api';
import { SANDBOX_LIMITS, type SandboxVersionFormInput } from '@/schemas/sandbox-schemas';

type HeldAgentFormProps = {
  control: Control<SandboxVersionFormInput>;
  errors: FormState<SandboxVersionFormInput>['errors'];
  register: UseFormRegister<SandboxVersionFormInput>;
};

/** The agent a version holds and the rules it works under. */
export function HeldAgentForm({ control, errors, register }: HeldAgentFormProps) {
  const t = useTranslations('dashboard.sandboxes.agent');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { data: agents } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug),
    queryKey: ['sandbox-agent-choices', orgSlug, tenantSlug],
    retry: false,
  });
  const { data: providers } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantModelProviders(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-model-providers', orgSlug, tenantSlug],
    retry: false,
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Controller
          control={control}
          name="agentId"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              error={errors.agentId}
              label={t('agent')}
              onChange={field.onChange}
              options={(agents ?? []).map((agent) => ({ label: agent.name, value: agent.id }))}
              placeholder={t('pickAgent')}
              value={field.value}
            />
          )}
        />
        <Controller
          control={control}
          name="providerId"
          render={({ field }) => (
            <Select
              className={fieldClassName}
              containerClassName={fieldContainerClassName}
              error={errors.providerId}
              label={t('provider')}
              onChange={field.onChange}
              options={(providers ?? [])
                .filter((provider) => provider.status === 'Active')
                .map((provider) => ({ label: provider.name, value: provider.id }))}
              placeholder={t('pickProvider')}
              value={field.value}
            />
          )}
        />
      </div>
      <Textarea
        {...register('goal')}
        className={fieldClassName}
        containerClassName={fieldContainerClassName}
        error={errors.goal}
        hint={t('goalHint')}
        label={t('goal')}
      />
      <Controller
        control={control}
        name="purpose"
        render={({ field }) => (
          <TagInput
            containerClassName={fieldContainerClassName}
            hint={t('purposeHint')}
            label={t('purpose')}
            onChange={field.onChange}
            placeholder={t('purposePlaceholder')}
            value={field.value}
          />
        )}
      />
      <Controller
        control={control}
        name="tools"
        render={({ field }) => (
          <TagInput
            containerClassName={fieldContainerClassName}
            hint={t('toolsHint')}
            label={t('tools')}
            onChange={field.onChange}
            value={field.value}
          />
        )}
      />
      <Controller
        control={control}
        name="approvalClasses"
        render={({ field }) => (
          <TagInput
            containerClassName={fieldContainerClassName}
            hint={t('approvalClassesHint')}
            label={t('approvalClasses')}
            onChange={field.onChange}
            value={field.value}
          />
        )}
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Input
          {...register('maxSteps', { valueAsNumber: true })}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          error={errors.maxSteps}
          hint={t('maxStepsHint', { most: SANDBOX_LIMITS.maxSteps })}
          label={t('maxSteps')}
          max={SANDBOX_LIMITS.maxSteps}
          min={1}
          type="number"
        />
        <Input
          {...register('tries', { valueAsNumber: true })}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          error={errors.tries}
          hint={t('triesHint', { most: SANDBOX_LIMITS.maxTries })}
          label={t('tries')}
          max={SANDBOX_LIMITS.maxTries}
          min={1}
          type="number"
        />
        <Input
          {...register('spendCap')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          error={errors.spendCap}
          hint={t('spendCapHint')}
          inputMode="decimal"
          label={t('spendCap')}
          placeholder="2"
        />
        <Input
          {...register('askPast')}
          className={fieldClassName}
          containerClassName={fieldContainerClassName}
          error={errors.askPast}
          hint={t('askPastHint')}
          inputMode="decimal"
          label={t('askPast')}
        />
      </div>
    </div>
  );
}
