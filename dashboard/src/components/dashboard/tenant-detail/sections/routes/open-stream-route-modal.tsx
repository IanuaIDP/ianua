'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { SegmentedControl } from '@/components/ui/segmented-control';
import { Textarea } from '@/components/ui/Textarea';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getApiErrorMessage, openStreamRouteToWorkflows } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { StreamRoute } from '@/types/stream-route';

type OpenStreamRouteModalProps = {
  onClose: () => void;
  open: boolean;
  route: StreamRoute;
};

const FORM_ID = 'open-stream-route-to-workflows';

/** Asks for the login workflows sign in with. The password is sent once and never kept here. */
export function OpenStreamRouteModal({ onClose, open, route }: OpenStreamRouteModalProps) {
  const t = useTranslations('dashboard.ports.actionModals.OpenToWorkflows');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const [loginUser, setLoginUser] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [tls, setTls] = useState<'off' | 'required'>('required');
  const [tlsAuthority, setTlsAuthority] = useState('');
  const [tlsServerName, setTlsServerName] = useState('');

  function close() {
    setLoginPassword('');
    onClose();
  }

  const { isPending, mutate } = useMutation({
    mutationFn: () =>
      openStreamRouteToWorkflows(orgSlug ?? '', tenantSlug, route.id, {
        loginPassword,
        loginUser,
        tls,
        tlsAuthority,
        tlsServerName,
      }),
    onError: (error) => {
      showNotification({ message: getApiErrorMessage(error, t('failed')), type: 'error' });
    },
    onSuccess: async () => {
      showNotification({ message: t('done'), type: 'success' });
      close();
      await queryClient.invalidateQueries({
        queryKey: ['tenant-stream-routes', orgSlug, tenantSlug],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
  });

  return (
    <Modal
      open={open}
      onClose={close}
      title={t('title')}
      description={t('description')}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={FORM_ID}
      isPrimaryActionDisabled={!loginUser.trim() || !loginPassword}
      isPrimaryActionLoading={isPending}
    >
      <form
        id={FORM_ID}
        onSubmit={(event) => {
          event.preventDefault();
          mutate();
        }}
      >
        <Input
          autoComplete="off"
          label={t('loginUser')}
          name="login_user"
          onChange={(event) => setLoginUser(event.target.value)}
          value={loginUser}
        />
        <Input
          autoComplete="new-password"
          label={t('loginPassword')}
          name="login_password"
          onChange={(event) => setLoginPassword(event.target.value)}
          type="password"
          value={loginPassword}
        />
        <div className="mb-6">
          <p className="mb-2 text-xs font-semibold text-white">{t('tls')}</p>
          <SegmentedControl
            ariaLabel={t('tls')}
            onChange={setTls}
            options={[
              { label: t('tlsRequired'), value: 'required' },
              { label: t('tlsOff'), value: 'off' },
            ]}
            value={tls}
          />
        </div>
        {tls === 'required' ? (
          <>
            <Textarea
              className="font-mono text-xs"
              hint={t('tlsAuthorityHint')}
              label={t('tlsAuthority')}
              name="tls_authority"
              onChange={(event) => setTlsAuthority(event.target.value)}
              rows={3}
              value={tlsAuthority}
            />
            <Input
              containerClassName="mb-0"
              hint={t('tlsServerNameHint')}
              label={t('tlsServerName')}
              name="tls_server_name"
              onChange={(event) => setTlsServerName(event.target.value)}
              value={tlsServerName}
            />
          </>
        ) : null}
      </form>
    </Modal>
  );
}
