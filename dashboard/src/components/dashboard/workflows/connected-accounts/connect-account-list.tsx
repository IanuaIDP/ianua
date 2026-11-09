'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { SearchInput } from '@/components/ui/search-input';
import { Select } from '@/components/ui/Select';
import { IntegrationMark } from '@/components/dashboard/workflows/integration-mark';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  beginWorkflowAccountConnection,
  connectWorkflowAccount,
  getApiErrorMessage,
} from '@/lib/api';
import { saveAccountConnectionTarget } from '@/lib/auth/account-connection';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { AccountSharing, WorkflowIntegration } from '@/types/workflows';
import { cn } from '@/utils/cn';

type ConnectServiceFormProps = {
  integration: WorkflowIntegration;
  onConnected: () => void;
};

/**
 * One service's sign-in or key field. The key lives only in this form's state
 * and leaves it only to be sent to the platform.
 */
function ConnectServiceForm({ integration, onConnected }: ConnectServiceFormProps) {
  const t = useTranslations('dashboard.connectedAccounts.connect');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [name, setName] = useState('');
  const [credential, setCredential] = useState('');
  const [place, setPlace] = useState('');
  const [sharing, setSharing] = useState<AccountSharing>('owner_only');
  const [error, setError] = useState<string | null>(null);
  const usesSignIn = integration.connecting === 'sign_in';
  const hasConnectionField = usesSignIn
    ? !integration.signInAsksFor || Boolean(place.trim())
    : Boolean(credential);
  const canSubmit = Boolean(name.trim()) && hasConnectionField;

  const { isPending, mutate } = useMutation({
    mutationFn: async () => {
      if (!usesSignIn) {
        await connectWorkflowAccount(orgSlug ?? '', tenantSlug, {
          credential,
          integration: integration.key,
          name,
          sharing,
        });

        return 'connected' as const;
      }

      const begun = await beginWorkflowAccountConnection(orgSlug ?? '', tenantSlug, {
        integration: integration.key,
        name,
        place: place || undefined,
        sharing,
      });

      saveAccountConnectionTarget({ orgSlug: orgSlug ?? '', tenantSlug });
      window.location.assign(begun.address);

      return 'signing-in' as const;
    },
    onError: (mutationError) => {
      setCredential('');
      setError(getApiErrorMessage(mutationError, t('failed')));
    },
    onSuccess: async (result) => {
      if (result === 'signing-in') {
        return;
      }

      showNotification({ message: t('connected'), type: 'success' });
      onConnected();
      await queryClient.invalidateQueries({ queryKey: ['workflow-accounts', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  return (
    <form
      className="flex flex-col gap-4 px-3 py-3"
      onSubmit={(event) => {
        event.preventDefault();

        if (canSubmit) {
          mutate();
        }
      }}
    >
      <Input
        containerClassName="mb-0"
        label={t('name')}
        onChange={(event) => setName(event.target.value)}
        placeholder={t('namePlaceholder')}
        value={name}
      />
      {usesSignIn ? null : (
        <Input
          autoComplete="off"
          containerClassName="mb-0"
          label={t('credential')}
          onChange={(event) => setCredential(event.target.value)}
          placeholder={t('credentialPlaceholder')}
          type="password"
          value={credential}
        />
      )}
      {usesSignIn && integration.signInAsksFor ? (
        <Input
          containerClassName="mb-0"
          label={t('place', { what: integration.signInAsksFor })}
          onChange={(event) => setPlace(event.target.value)}
          value={place}
        />
      ) : null}
      <Select
        containerClassName="mb-0"
        label={t('sharing')}
        onChange={(value) => setSharing(value as AccountSharing)}
        options={[
          { label: t('sharingOwner'), value: 'owner_only' },
          { label: t('sharingTenant'), value: 'tenant' },
        ]}
        value={sharing}
      />
      {error ? (
        <p
          className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error"
          role="alert"
        >
          {error}
        </p>
      ) : null}
      <div>
        <Button type="submit" disabled={!canSubmit || isPending} isLoading={isPending}>
          {usesSignIn ? t('signInAction') : t('connectAction')}
        </Button>
      </div>
    </form>
  );
}

type ConnectAccountListProps = {
  integrations: WorkflowIntegration[];
  onClose: () => void;
};

/** A popup listing the services; selecting a row shows that service's field beneath it. */
export function ConnectAccountList({ integrations, onClose }: ConnectAccountListProps) {
  const t = useTranslations('dashboard.connectedAccounts.connect');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const term = search.trim().toLowerCase();
  const shown = integrations.filter((item) => item.title.toLowerCase().includes(term));

  return (
    <Modal open onClose={onClose} title={t('title')}>
      <SearchInput
        onChange={(event) => setSearch(event.target.value)}
        onClear={() => setSearch('')}
        placeholder={t('searchPlaceholder')}
        value={search}
      />
      <ul className="mt-3 max-h-96 divide-y divide-borderGray overflow-y-auto rounded-lg border border-borderGray">
        {shown.map((integration) => {
          const isSelected = integration.key === selectedKey;

          return (
            <li key={integration.key}>
              <button
                type="button"
                aria-expanded={isSelected}
                onClick={() => setSelectedKey(isSelected ? null : integration.key)}
                className={cn(
                  'flex w-full items-center gap-2.5 px-3 py-2.5 text-left text-xs font-semibold text-white transition hover:bg-hoverBg',
                  isSelected && 'bg-primary/15',
                )}
              >
                <IntegrationMark integration={integration} />
                {integration.title}
              </button>
              {isSelected ? (
                <ConnectServiceForm
                  key={integration.key}
                  integration={integration}
                  onConnected={onClose}
                />
              ) : null}
            </li>
          );
        })}
      </ul>
    </Modal>
  );
}
