'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { changeWorkflowAccount, getApiErrorMessage } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { WorkflowAccount, WorkflowOperation } from '@/types/workflows';

export type AccountChangeKind = 'Rename' | 'Replace' | 'Limit';

type AccountChangeModalProps = {
  account: WorkflowAccount;
  kind: AccountChangeKind;
  onClose: () => void;
  onDone: (message: string) => void;
  operations: WorkflowOperation[];
};

/** Renames an account, replaces its key, or limits it to some operations. */
export function AccountChangeModal({
  account,
  kind,
  onClose,
  onDone,
  operations,
}: AccountChangeModalProps) {
  const t = useTranslations('dashboard.connectedAccounts.change');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const [name, setName] = useState(account.name);
  const [credential, setCredential] = useState('');
  const [limited, setLimited] = useState<string[]>(account.operations ?? []);
  const [error, setError] = useState<string | null>(null);
  const available = operations.filter((operation) => operation.integration === account.integration);
  const isReady =
    kind === 'Rename' ? Boolean(name.trim()) : kind === 'Replace' ? Boolean(credential) : true;

  const { isPending, mutate } = useMutation({
    mutationFn: () =>
      changeWorkflowAccount(
        orgSlug ?? '',
        tenantSlug,
        account.id,
        kind === 'Rename'
          ? { change: 'rename', name }
          : kind === 'Replace'
            ? { change: 'replace_credential', credential }
            : { change: 'limit_to', operations: limited.length > 0 ? limited : null },
      ),
    onError: (mutationError) => {
      setCredential('');
      setError(getApiErrorMessage(mutationError, t('failed')));
    },
    onSuccess: async () => {
      onDone(t(`done${kind}`));
      await queryClient.invalidateQueries({ queryKey: ['workflow-accounts', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  return (
    <Modal
      open
      onClose={onClose}
      title={t(`title${kind}`, { name: account.name })}
      showCloseButton={false}
      primaryActionLabel={t('save')}
      onPrimaryAction={() => mutate()}
      isPrimaryActionLoading={isPending}
      isPrimaryActionDisabled={!isReady || isPending}
    >
      <div className="flex flex-col gap-4">
        {kind === 'Rename' ? (
          <Input
            containerClassName="mb-0"
            label={t('name')}
            onChange={(event) => setName(event.target.value)}
            value={name}
          />
        ) : null}
        {kind === 'Replace' ? (
          <Input
            autoComplete="off"
            containerClassName="mb-0"
            label={t('credential')}
            onChange={(event) => setCredential(event.target.value)}
            type="password"
            value={credential}
          />
        ) : null}
        {kind === 'Limit' ? (
          <MultiSelect
            containerClassName="mb-0"
            hint={t('limitHint')}
            label={t('limit')}
            onChange={setLimited}
            options={available.map((operation) => ({
              label: operation.title,
              value: operation.operation,
            }))}
            placeholder={t('limitPlaceholder')}
            value={limited}
          />
        ) : null}
        {error ? (
          <p
            className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error"
            role="alert"
          >
            {error}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
