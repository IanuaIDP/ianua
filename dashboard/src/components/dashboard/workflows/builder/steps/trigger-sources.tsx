'use client';

import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { PanelField, PanelNote } from '@/components/dashboard/workflows/builder/panel-field';
import { useWorkflowRouteParams } from '@/components/dashboard/workflows/builder/use-workflow-route-params';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import {
  getApiErrorMessage,
  getCompanyEventTypes,
  getWorkflowServiceEvents,
  issueWorkflowTriggerSecret,
  revokeWorkflowTriggerSecret,
  rotateWorkflowTriggerSecret,
  type WorkflowTriggerSecret,
} from '@/lib/api';
import type { WorkflowTrigger } from '@/types/workflow-graph';

const BEFORE_CHANGES = [
  'access_given',
  'admin_given',
  'app_opened_to_workflows',
  'audit_exported',
] as const;

type TriggerOf<Type extends WorkflowTrigger['type']> = Extract<WorkflowTrigger, { type: Type }>;

type TriggerFieldsProps<Type extends WorkflowTrigger['type']> = {
  disabled: boolean;
  onChange: (next: TriggerOf<Type>) => void;
  trigger: TriggerOf<Type>;
};

/** Starts a workflow on something that happens in the tenant, such as a user added. */
export function CompanyEventFields({ disabled, onChange, trigger }: TriggerFieldsProps<'event'>) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');
  const { orgSlug, tenantSlug } = useWorkflowRouteParams();
  const { data: events, isError } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getCompanyEventTypes(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-company-events', orgSlug, tenantSlug],
  });

  if (isError) {
    return (
      <PanelField hint={t('eventTypedHint')} label={t('eventField')}>
        <Input
          aria-label={t('eventField')}
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(event) => onChange({ event: event.target.value, type: 'event' })}
          placeholder="identity.user_registered"
          value={trigger.event}
        />
      </PanelField>
    );
  }

  return (
    <PanelField label={t('eventField')}>
      <Select
        containerClassName="mb-0"
        disabled={disabled}
        onChange={(event) => onChange({ event, type: 'event' })}
        options={(events ?? []).map((event) => ({ label: event.description, value: event.name }))}
        placeholder={t('eventPlaceholder')}
        value={trigger.event}
      />
    </PanelField>
  );
}

/** Starts a workflow on something a connected service sends. */
export function ServiceEventFields({ disabled, onChange, trigger }: TriggerFieldsProps<'service'>) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');
  const { orgSlug, tenantSlug } = useWorkflowRouteParams();
  const { accounts, text } = useBuilderContext();
  const { data: events } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getWorkflowServiceEvents(orgSlug ?? '', tenantSlug),
    queryKey: ['workflow-service-events', orgSlug, tenantSlug],
  });
  const connected = accounts.filter((account) => account.status === 'enabled');
  const serviceAccounts = connected.filter(
    (account) => account.integration === trigger.integration,
  );
  const services = [...new Set(connected.map((account) => account.integration))].filter(
    (integration) => events?.some((event) => event.integration === integration),
  );
  const serviceEvents = (events ?? []).filter((event) => event.integration === trigger.integration);
  const chosen = serviceEvents.find((event) => event.event === trigger.event);

  function chooseService(integration: string) {
    onChange({
      account_id: connected.find((account) => account.integration === integration)?.id ?? '',
      event: '',
      integration,
      type: 'service',
    });
  }

  function setFilter(name: string, value: string) {
    onChange({ ...trigger, filters: { ...trigger.filters, [name]: value } });
  }

  if (services.length === 0 && !trigger.integration) {
    return <PanelNote icon="link_off">{t('noServices')}</PanelNote>;
  }

  return (
    <>
      <PanelField label={t('serviceField')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={chooseService}
          options={services.map((integration) => ({
            label: text.getIntegrationTitle(integration),
            value: integration,
          }))}
          placeholder={t('servicePlaceholder')}
          value={trigger.integration}
        />
      </PanelField>
      {trigger.integration ? (
        <PanelField label={t('serviceEvent')}>
          <Select
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => onChange({ ...trigger, event, filters: undefined })}
            options={serviceEvents.map((event) => ({ label: event.title, value: event.event }))}
            placeholder={t('serviceEventPlaceholder')}
            value={trigger.event}
          />
        </PanelField>
      ) : null}
      {serviceAccounts.length > 1 ? (
        <PanelField label={t('account')}>
          <Select
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(accountId) => onChange({ ...trigger, account_id: accountId })}
            options={serviceAccounts.map((account) => ({
              label: account.name,
              value: account.id,
            }))}
            value={trigger.account_id}
          />
        </PanelField>
      ) : null}
      {chosen?.filters.map((filter) => (
        <PanelField hint={filter.description} key={filter.name} label={filter.name}>
          <Input
            aria-label={filter.name}
            containerClassName="mb-0"
            disabled={disabled}
            onChange={(event) => setFilter(filter.name, event.target.value)}
            value={trigger.filters?.[filter.name] ?? ''}
          />
        </PanelField>
      ))}
    </>
  );
}

/** Starts a workflow before a guarded change, which it then allows or refuses. */
export function BeforeChangeFields({ disabled, onChange, trigger }: TriggerFieldsProps<'before'>) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');
  const tChange = useLooseTranslations('dashboard.workflowBuilder.text.beforeChanges');

  return (
    <>
      <PanelField label={t('beforeChange')}>
        <Select
          containerClassName="mb-0"
          disabled={disabled}
          onChange={(change) => onChange({ change, type: 'before' })}
          options={BEFORE_CHANGES.map((change) => ({ label: tChange(change), value: change }))}
          value={trigger.change}
        />
      </PanelField>
      <PanelNote icon="gavel">{t('beforeHelp')}</PanelNote>
      <PanelNote icon="warning" tone="warning">
        {t('beforeWarning')}
      </PanelNote>
    </>
  );
}

/** Issues the secret another system calls this workflow with. */
export function WebhookFields({ disabled }: { disabled: boolean }) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');
  const { orgSlug, tenantSlug, workflowId } = useWorkflowRouteParams();
  const { showNotification } = useNotification();
  const copy = useCopyToClipboard();
  const [issued, setIssued] = useState<WorkflowTriggerSecret | null>(null);
  const [isRevoked, setIsRevoked] = useState(false);
  const slug = orgSlug ?? '';
  const id = workflowId ?? '';

  function showFailure(error: unknown) {
    showNotification({ message: getApiErrorMessage(error, t('secretFailed')), type: 'error' });
  }

  const issue = useMutation({
    mutationFn: (kind: 'issue' | 'rotate') =>
      kind === 'issue'
        ? issueWorkflowTriggerSecret(slug, tenantSlug, id)
        : rotateWorkflowTriggerSecret(slug, tenantSlug, id),
    onError: showFailure,
    onSuccess: (secret) => {
      setIsRevoked(false);
      setIssued(secret);
    },
  });
  const revoke = useMutation({
    mutationFn: () => revokeWorkflowTriggerSecret(slug, tenantSlug, id),
    onError: showFailure,
    onSuccess: () => setIsRevoked(true),
  });

  if (!workflowId) {
    return <PanelNote icon="info">{t('webhookSaveFirst')}</PanelNote>;
  }

  const isBusy = disabled || issue.isPending || revoke.isPending;
  const address = issued
    ? `/api/v1/organizations/${slug}/tenants/${tenantSlug}/workflows/triggers/${issued.triggerId}`
    : '';

  return (
    <>
      <PanelNote icon="webhook">{t('webhookHelp')}</PanelNote>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button disabled={isBusy} onClick={() => issue.mutate('issue')} type="button">
          {t('secretIssue')}
        </Button>
        <Button
          disabled={isBusy}
          onClick={() => issue.mutate('rotate')}
          type="button"
          variant="outline"
        >
          {t('secretReplace')}
        </Button>
        <Button disabled={isBusy} onClick={() => revoke.mutate()} type="button" variant="outline">
          {t('secretRevoke')}
        </Button>
      </div>
      {isRevoked ? <PanelNote icon="check">{t('secretRevoked')}</PanelNote> : null}

      <Modal
        autoFocus={false}
        description={t('secretOnce')}
        dismissible={false}
        onClose={() => setIssued(null)}
        onPrimaryAction={() => setIssued(null)}
        open={Boolean(issued)}
        primaryActionLabel={t('secretDone')}
        showCancelButton={false}
        showCloseButton={false}
        title={t('secretTitle')}
      >
        <div className="space-y-3">
          <SecretRow label={t('secretAddress')} value={`POST ${address}`} onCopy={copy} />
          <SecretRow
            label={t('secretHeader')}
            value={`Ianua-Trigger-Secret: ${issued?.secret ?? ''}`}
            onCopy={copy}
          />
        </div>
      </Modal>
    </>
  );
}

type SecretRowProps = {
  label: string;
  onCopy: (value: string, successMessage: string) => Promise<boolean>;
  value: string;
};

function SecretRow({ label, onCopy, value }: SecretRowProps) {
  const t = useTranslations('dashboard.workflowBuilder.trigger');

  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-borderGray px-4 py-3">
      <div className="min-w-0">
        <p className="text-xs font-medium text-textGray">{label}</p>
        <p className="mt-1 break-all font-mono text-xs text-white">{value}</p>
      </div>
      <button
        type="button"
        aria-label={t('secretCopy')}
        onClick={() => void onCopy(value, t('secretCopied'))}
        className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:text-white"
      >
        <span className="material-symbols-rounded">content_copy</span>
      </button>
    </div>
  );
}
