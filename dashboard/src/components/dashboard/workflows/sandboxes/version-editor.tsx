'use client';

import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import Link from 'next/link';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { CodeEditor } from '@/components/dashboard/workflows/sandboxes/code-editor-loader';
import { HeldAgentForm } from '@/components/dashboard/workflows/sandboxes/held-agent-form';
import { PackageList } from '@/components/dashboard/workflows/sandboxes/package-list';
import { useRepositoryAccounts } from '@/components/dashboard/workflows/sandboxes/use-repository-accounts';
import {
  isStarterCode,
  starterCheck,
  type VersionSeed,
} from '@/components/dashboard/workflows/sandboxes/version-seed';
import { WriteCodeModal } from '@/components/dashboard/workflows/sandboxes/write-code-modal';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { useNotification } from '@/components/ui/notifications';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { TagInput } from '@/components/ui/TagInput';
import { useValidationText } from '@/hooks/i18n/use-field-error';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, getSandboxRuntimes, saveSandboxVersion } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import {
  SANDBOX_LIMITS,
  SandboxVersionSchema,
  type SandboxVersionFormInput,
} from '@/schemas/sandbox-schemas';
import type {
  Sandbox,
  SandboxRuntime,
  SandboxVersion,
  SaveSandboxVersionInput,
} from '@/types/sandbox';
import { getTenantScopedPath } from '@/utils/dashboard-routes';
import { amountFromMicros, microsFromAmount } from '@/utils/micros';

type VersionEditorProps = {
  onCancel: () => void;
  onSaved: (version: SandboxVersion) => void;
  sandbox: Sandbox;
  seed: VersionSeed;
};

function offeredRuntimes(runtimes: SandboxRuntime[], language: string | null) {
  return runtimes.filter((runtime) => runtime.language === language);
}

function toFormValues(
  sandbox: Sandbox,
  seed: VersionSeed,
  runtimes: SandboxRuntime[],
): SandboxVersionFormInput {
  const seededIsOffered = runtimes.some((runtime) => runtime.runtime === seed.runtime);

  return {
    accountId: '',
    agentId: seed.agent?.agentId ?? '',
    allowedHosts: seed.allowedHosts,
    approvalClasses: seed.agent?.approvalClasses ?? [],
    askPast:
      seed.agent?.askPastMicros !== null && seed.agent?.askPastMicros !== undefined
        ? amountFromMicros(seed.agent.askPastMicros)
        : '',
    code: seed.code,
    goal: seed.agent?.goal ?? '',
    holdsAgent: Boolean(seed.agent),
    image: seed.image,
    kind: sandbox.kind === 'image' ? 'image' : 'code',
    maxSteps: seed.agent?.maxSteps ?? 10,
    memoryMib: seed.memoryMib,
    packages: seed.packages,
    path: '',
    providerId: seed.agent?.providerId ?? '',
    purpose: seed.agent?.purpose ?? [],
    ref: 'main',
    repository: '',
    runSeconds: seed.runSeconds,
    runtime: seededIsOffered ? seed.runtime : (runtimes[0]?.runtime ?? ''),
    source: 'write',
    spendCap: seed.agent ? amountFromMicros(seed.agent.spendCapMicros) : '',
    tools: seed.agent?.tools ?? [],
    tries: seed.agent?.tries ?? 1,
  };
}

function toSaveInput(values: SandboxVersionFormInput): SaveSandboxVersionInput {
  const limits = {
    allowedHosts: values.allowedHosts,
    memoryMib: values.memoryMib,
    runSeconds: values.runSeconds,
  };

  if (values.kind === 'image') {
    return {
      ...limits,
      agent: null,
      code: null,
      image: values.image.trim(),
      import: null,
      packages: [],
      runtime: null,
    };
  }

  return {
    ...limits,
    agent: values.holdsAgent
      ? {
          agentId: values.agentId,
          approvalClasses: values.approvalClasses,
          askPastMicros: values.askPast.trim() ? microsFromAmount(values.askPast) : null,
          goal: values.goal.trim(),
          maxSteps: values.maxSteps,
          providerId: values.providerId,
          purpose: values.purpose,
          spendCapMicros: microsFromAmount(values.spendCap) ?? 0,
          tools: values.tools,
          tries: values.tries,
        }
      : null,
    code: values.source === 'write' ? values.code : null,
    image: null,
    import:
      values.source === 'import'
        ? {
            accountId: values.accountId,
            path: values.path.trim(),
            ref: values.ref.trim(),
            repository: values.repository.trim(),
          }
        : null,
    packages: values.packages,
    runtime: values.runtime,
  };
}

/** Loads what the form needs, so the form opens with a runtime that is still offered. */
export function VersionEditor(props: VersionEditorProps) {
  const t = useTranslations('dashboard.sandboxes.editor');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const isImage = props.sandbox.kind === 'image';
  const { data: runtimes, isLoading } = useQuery({
    enabled: !isImage && Boolean(orgSlug && tenantSlug),
    queryFn: () => getSandboxRuntimes(orgSlug ?? '', tenantSlug),
    queryKey: ['sandbox-runtimes', orgSlug, tenantSlug],
  });

  if (!isImage && isLoading) {
    return <p className="text-sm text-textGray">{t('loading')}</p>;
  }

  return (
    <VersionForm {...props} runtimes={offeredRuntimes(runtimes ?? [], props.sandbox.language)} />
  );
}

const editorFormId = 'sandbox-version-form';

function VersionForm({
  onCancel,
  onSaved,
  runtimes,
  sandbox,
  seed,
}: VersionEditorProps & { runtimes: SandboxRuntime[] }) {
  const t = useTranslations('dashboard.sandboxes.editor');
  const { isTenantView, orgSlug, tenantSlug } = useTenantRouteParams();
  const { hasPermission } = useTenantPermissions();
  const validationText = useValidationText();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { accounts } = useRepositoryAccounts();
  const [isWriting, setIsWriting] = useState(false);
  const [explanation, setExplanation] = useState(seed.explanation);
  const {
    control,
    formState: { errors },
    getValues,
    handleSubmit,
    register,
    setValue,
  } = useForm<SandboxVersionFormInput>({
    defaultValues: toFormValues(sandbox, seed, runtimes),
    resolver: zodResolver(SandboxVersionSchema),
  });
  const isImage = sandbox.kind === 'image';
  const language = sandbox.language ?? 'python';
  const source = useWatch({ control, name: 'source' });
  const holdsAgent = useWatch({ control, name: 'holdsAgent' });
  const hosts = useWatch({ control, name: 'allowedHosts' });
  const { isPending, mutate } = useMutation({
    mutationFn: (values: SandboxVersionFormInput) =>
      saveSandboxVersion(orgSlug ?? '', tenantSlug, sandbox.id, toSaveInput(values)),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async (version) => {
      showNotification({ message: t('saved', { number: version.number }), type: 'success' });
      await queryClient.invalidateQueries({ queryKey: ['sandbox', orgSlug, tenantSlug] });
      await queryClient.invalidateQueries({ queryKey: ['sandboxes', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onSaved(version);
    },
  });

  return (
    <section className="rounded-lg border border-borderGray bg-cardBg p-4">
      <h2 className="text-base font-bold text-white">{t('title')}</h2>
      <p className="mt-1 text-xs text-textGray">{t('description')}</p>
      <form
        id={editorFormId}
        className="mt-4 flex flex-col gap-4"
        onSubmit={handleSubmit((values) => mutate(values))}
      >
        {explanation ? (
          <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs text-textGray">
            <span className="font-semibold text-white">{t('modelSays')}</span> {explanation}
          </p>
        ) : null}

        {isImage ? (
          <Input
            {...register('image')}
            className={fieldClassName}
            containerClassName={fieldContainerClassName}
            disabled={isPending}
            error={errors.image}
            hint={t('imageHint')}
            label={t('image')}
            placeholder={t('imagePlaceholder')}
          />
        ) : (
          <>
            <SegmentedControl<'write' | 'import'>
              ariaLabel={t('source')}
              options={[
                { label: t('sourceWrite'), value: 'write' },
                { label: t('sourceImport'), value: 'import' },
              ]}
              value={source}
              onChange={(next) => setValue('source', next)}
            />

            {source === 'write' ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-semibold text-white">{t('code')}</p>
                  <button
                    className="text-xs font-semibold text-primary hover:underline"
                    type="button"
                    onClick={() => setIsWriting(true)}
                  >
                    {t('writeWithModel')}
                  </button>
                </div>
                <Controller
                  control={control}
                  name="code"
                  render={({ field }) => (
                    <CodeEditor
                      ariaLabel={t('code')}
                      language={language}
                      value={field.value}
                      onChange={field.onChange}
                    />
                  )}
                />
                {errors.code?.message ? (
                  <p className="text-xs text-error">{validationText(errors.code.message)}</p>
                ) : null}
                <p className="text-xs text-textGray">
                  {language === 'javascript' ? t('codeHintJavascript') : t('codeHintPython')}
                </p>
              </div>
            ) : (
              <div className="flex flex-col gap-4">
                {accounts.length === 0 ? (
                  <p className="rounded-lg bg-surfaceChip px-3 py-2 text-xs text-textGray">
                    {t.rich('noRepositoryAccount', {
                      link: (chunks) => (
                        <Link
                          className="font-semibold text-primary hover:underline"
                          href={getTenantScopedPath(
                            isTenantView,
                            orgSlug,
                            tenantSlug,
                            'connected-accounts',
                            'connected-accounts',
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
                  name="accountId"
                  render={({ field }) => (
                    <Select
                      className={fieldClassName}
                      containerClassName={fieldContainerClassName}
                      error={errors.accountId}
                      label={t('account')}
                      onChange={field.onChange}
                      options={accounts.map((account) => ({
                        label: account.name,
                        value: account.id,
                      }))}
                      placeholder={t('pickAccount')}
                      value={field.value}
                    />
                  )}
                />
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <Input
                    {...register('repository')}
                    className={fieldClassName}
                    containerClassName={fieldContainerClassName}
                    error={errors.repository}
                    label={t('repository')}
                    placeholder="acme/web"
                  />
                  <Input
                    {...register('path')}
                    className={fieldClassName}
                    containerClassName={fieldContainerClassName}
                    error={errors.path}
                    label={t('path')}
                    placeholder="scripts/tidy.py"
                  />
                  <Input
                    {...register('ref')}
                    className={fieldClassName}
                    containerClassName={fieldContainerClassName}
                    error={errors.ref}
                    label={t('ref')}
                  />
                </div>
                <p className="text-xs text-textGray">{t('importHint')}</p>
              </div>
            )}

            <PackageList control={control} errors={errors} register={register} />

            <Controller
              control={control}
              name="runtime"
              render={({ field }) => (
                <Select
                  className={fieldClassName}
                  containerClassName={fieldContainerClassName}
                  error={errors.runtime}
                  hint={t('runtimeHint')}
                  label={t('runtime')}
                  onChange={field.onChange}
                  options={runtimes.map((runtime) => ({
                    label: runtime.runtime,
                    value: runtime.runtime,
                  }))}
                  value={field.value}
                />
              )}
            />
          </>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Input
            {...register('runSeconds', { valueAsNumber: true })}
            className={fieldClassName}
            containerClassName={fieldContainerClassName}
            error={errors.runSeconds}
            hint={t('runSecondsHint', {
              least: SANDBOX_LIMITS.minRunSeconds,
              most: SANDBOX_LIMITS.maxRunSeconds,
            })}
            label={t('runSeconds')}
            max={SANDBOX_LIMITS.maxRunSeconds}
            min={SANDBOX_LIMITS.minRunSeconds}
            type="number"
          />
          <Input
            {...register('memoryMib', { valueAsNumber: true })}
            className={fieldClassName}
            containerClassName={fieldContainerClassName}
            error={errors.memoryMib}
            hint={t('memoryHint', {
              least: SANDBOX_LIMITS.minMemoryMib,
              most: SANDBOX_LIMITS.maxMemoryMib,
            })}
            label={t('memory')}
            max={SANDBOX_LIMITS.maxMemoryMib}
            min={SANDBOX_LIMITS.minMemoryMib}
            type="number"
          />
        </div>

        <Controller
          control={control}
          name="allowedHosts"
          render={({ field }) => (
            <TagInput
              containerClassName={fieldContainerClassName}
              error={errors.allowedHosts?.message}
              hint={t('hostsHint')}
              label={t('hosts')}
              onChange={field.onChange}
              placeholder={t('hostsPlaceholder')}
              value={field.value}
            />
          )}
        />
        {hosts.length > 0 ? (
          <p className="rounded-lg bg-orange/10 px-3 py-2 text-xs text-orange">
            {t('hostsWarning')}
          </p>
        ) : null}

        {!isImage ? (
          <>
            <Controller
              control={control}
              name="holdsAgent"
              render={({ field }) => (
                <Switch
                  checked={field.value}
                  description={t('holdsAgentHint')}
                  label={t('holdsAgent')}
                  onCheckedChange={(checked) => {
                    field.onChange(checked);

                    if (checked && isStarterCode(getValues('code'), sandbox.language)) {
                      setValue('code', starterCheck(sandbox.language));
                    }
                  }}
                />
              )}
            />
            {holdsAgent ? (
              <HeldAgentForm control={control} errors={errors} register={register} />
            ) : null}
          </>
        ) : null}

        <div className="flex justify-end gap-2">
          <Button disabled={isPending} type="button" variant="outline" onClick={onCancel}>
            {t('cancel')}
          </Button>
          <Button disabled={isPending} isLoading={isPending} type="submit">
            {t('save')}
          </Button>
        </div>
      </form>

      {hasPermission('Workflows', 'Update') ? (
        <WriteCodeModal
          open={isWriting}
          packages={getValues('packages').map((item) => item.name)}
          sandboxId={sandbox.id}
          onClose={() => setIsWriting(false)}
          onWritten={(written) => {
            setValue('code', written.code);
            setExplanation(written.explanation);
            setIsWriting(false);
          }}
        />
      ) : null}
    </section>
  );
}
