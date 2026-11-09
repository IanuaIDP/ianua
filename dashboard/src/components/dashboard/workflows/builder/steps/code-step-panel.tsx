'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { MappedFieldsEditor } from '@/components/dashboard/workflows/builder/steps/mapped-fields-editor';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Select } from '@/components/ui/Select';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, getRunnableSandboxVersions } from '@/lib/api';
import type { WorkflowCodeStep, WorkflowNode } from '@/types/workflow-graph';

type CodeNode = WorkflowNode & WorkflowCodeStep;

/** Picks the saved sandbox version a code step runs and the fields it is handed. */
export function CodeStepPanel({ disabled, node }: { disabled: boolean; node: CodeNode }) {
  const t = useTranslations('dashboard.sandboxes.codeStep');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const updateNode = useWorkingCopy((state) => state.updateNode);
  const { data, error, isLoading } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug),
    queryFn: () => getRunnableSandboxVersions(orgSlug ?? '', tenantSlug),
    queryKey: ['sandbox-runnable-versions', orgSlug, tenantSlug],
    retry: false,
  });
  const choices = data ?? [];
  const picked = choices.find((choice) => choice.version.id === node.sandbox_version_id);
  const isUnavailable = Boolean(data) && Boolean(node.sandbox_version_id) && !picked;

  return (
    <>
      <PanelField hint={t('hint')} label={t('version')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled || isLoading}
          onChange={(sandboxVersionId) =>
            updateNode(node.key, (current) => ({
              ...current,
              sandbox_version_id: sandboxVersionId,
            }))
          }
          options={choices.map(({ sandbox, version }) => ({
            label: t('option', { name: sandbox.name, number: version.number }),
            value: version.id,
          }))}
          placeholder={t('pick')}
          value={picked ? node.sandbox_version_id : ''}
        />
      </PanelField>

      {error ? (
        <PanelNote icon="error" tone="danger">
          {getApiErrorMessage(error, t('loadFailed'))}
        </PanelNote>
      ) : null}

      {data && choices.length === 0 ? <PanelNote icon="info">{t('none')}</PanelNote> : null}

      {isUnavailable ? (
        <PanelNote icon="warning" tone="warning">
          {t('unavailable')}
        </PanelNote>
      ) : null}

      {picked?.version.runtime ? (
        <PanelNote icon="code_blocks">
          {t('runtime', { runtime: picked.version.runtime })}
        </PanelNote>
      ) : null}

      {picked && picked.version.allowedHosts.length > 0 ? (
        <PanelNote icon="warning" tone="warning">
          {t('network', { hosts: picked.version.allowedHosts.join(', ') })}
        </PanelNote>
      ) : null}

      {picked && picked.version.allowedHosts.length === 0 ? (
        <PanelNote icon="info">{t('noNetwork')}</PanelNote>
      ) : null}

      <MappedFieldsEditor
        disabled={disabled}
        fields={node.inputs}
        label={t('inputs')}
        onChange={(inputs) => updateNode(node.key, (current) => ({ ...current, inputs }))}
        stepKey={node.key}
      />
    </>
  );
}
