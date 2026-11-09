'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  confirmAccountChannel,
  getAccountChannel,
  getApiErrorMessage,
  setAccountChannelKey,
  showAccountChannelToken,
  type AccountChannel,
} from '@/lib/api';
import type { WorkflowAccount } from '@/types/workflows';

type AccountChannelModalProps = {
  account: WorkflowAccount;
  onClose: () => void;
};

type CopyRowProps = {
  label: string;
  value: string;
};

function CopyRow({ label, value }: CopyRowProps) {
  const t = useTranslations('dashboard.connectedAccounts.channel');
  const copy = useCopyToClipboard();

  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-borderGray px-4 py-3">
      <div className="min-w-0">
        <p className="text-xs font-medium text-textGray">{label}</p>
        <p className="mt-1 break-all font-mono text-xs text-white">{value}</p>
      </div>
      <button
        type="button"
        aria-label={t('copy')}
        onClick={() => void copy(value, t('copied'))}
        className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:text-white"
      >
        <span className="material-symbols-rounded">content_copy</span>
      </button>
    </div>
  );
}

/** The one address a service sends an account's events to, and its setup. */
export function AccountChannelModal({ account, onClose }: AccountChannelModalProps) {
  const t = useTranslations('dashboard.connectedAccounts.channel');
  const tStatus = useLooseTranslations('dashboard.connectedAccounts.channel.status');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const queryClient = useQueryClient();
  const [key, setKey] = useState('');
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const slug = orgSlug ?? '';
  const queryKey = ['account-channel', orgSlug, tenantSlug, account.id];
  const {
    data: channel,
    isError,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug),
    queryFn: () => getAccountChannel(slug, tenantSlug, account.id),
    queryKey,
    retry: false,
  });

  function keepChannel(next: AccountChannel) {
    setError(null);
    queryClient.setQueryData(queryKey, next);
  }

  function showFailure(mutationError: unknown) {
    setError(getApiErrorMessage(mutationError, t('failed')));
  }

  const saveKey = useMutation({
    mutationFn: () => setAccountChannelKey(slug, tenantSlug, account.id, key),
    onError: showFailure,
    onSuccess: (next) => {
      setKey('');
      keepChannel(next);
    },
  });
  const showToken = useMutation({
    mutationFn: () => showAccountChannelToken(slug, tenantSlug, account.id),
    onError: showFailure,
    onSuccess: setToken,
  });
  const confirm = useMutation({
    mutationFn: () => confirmAccountChannel(slug, tenantSlug, account.id),
    onError: showFailure,
    onSuccess: (next) => {
      setToken(null);
      keepChannel(next);
    },
  });

  return (
    <Modal open onClose={onClose} title={t('title', { name: account.name })}>
      {isLoading ? <p className="text-sm text-textGray">{t('loading')}</p> : null}
      {isError ? <p className="text-sm text-textGray">{t('none')}</p> : null}
      {channel ? (
        <div className="space-y-3">
          <p className="text-sm text-white">{tStatus(channel.status)}</p>
          <CopyRow label={t('address')} value={channel.address} />

          {channel.status === 'awaiting_key' ? (
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                saveKey.mutate();
              }}
            >
              <Input
                autoComplete="off"
                containerClassName="mb-0"
                label={t('key')}
                onChange={(event) => setKey(event.target.value)}
                type="password"
                value={key}
              />
              <Button type="submit" disabled={!key} isLoading={saveKey.isPending}>
                {t('saveKey')}
              </Button>
            </form>
          ) : null}

          {channel.status === 'awaiting_confirmation' ? (
            <>
              {token ? <CopyRow label={t('token')} value={token} /> : null}
              <div className="flex flex-wrap gap-2">
                {token ? null : (
                  <Button
                    type="button"
                    variant="outline"
                    isLoading={showToken.isPending}
                    onClick={() => showToken.mutate()}
                  >
                    {t('showToken')}
                  </Button>
                )}
                <Button
                  type="button"
                  isLoading={confirm.isPending}
                  onClick={() => confirm.mutate()}
                >
                  {t('confirm')}
                </Button>
              </div>
            </>
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
      ) : null}
    </Modal>
  );
}
