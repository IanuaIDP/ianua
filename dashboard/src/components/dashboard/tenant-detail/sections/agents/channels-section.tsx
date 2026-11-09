'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { DashboardDataCard } from '@/components/dashboard/shared/dashboard-data-card';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { TableCellText } from '@/components/ui/table-cell';
import { useAgentRouteParams } from '@/hooks/tenants/use-agent-route-params';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import {
  closeAgentChannel,
  deriveErrorMessage,
  getAgentChannels,
  getApiErrorMessage,
  getTenantAgents,
  openAgentChannel,
  type AgentChannel,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TenantAgent } from '@/types/tenant-agent';
import { formatBackendDateTime } from '@/utils/date';

const CLASSES = ['Public', 'Internal', 'Confidential', 'Restricted'];
const HOUR = 3600;
const LIFETIMES = [
  { key: 'hour', seconds: HOUR },
  { key: 'day', seconds: 24 * HOUR },
  { key: 'week', seconds: 7 * 24 * HOUR },
  { key: 'month', seconds: 30 * 24 * HOUR },
] as const;

type OpenChannelModalProps = {
  agentId: string;
  agents: TenantAgent[];
  onClose: () => void;
  onOpened: () => Promise<void>;
};

function OpenChannelModal({ agentId, agents, onClose, onOpened }: OpenChannelModalProps) {
  const t = useTranslations('dashboard.agentChannels');
  const topicArea = `agents.${agentId.replaceAll('-', '')}`;
  const { orgSlug, tenantSlug } = useAgentRouteParams();
  const [receiver, setReceiver] = useState('');
  const [kind, setKind] = useState<'topics' | 'resource'>('topics');
  const [scope, setScope] = useState(`${topicArea}.>`);
  const [maxClass, setMaxClass] = useState('Internal');
  const [lifetime, setLifetime] = useState(String(24 * HOUR));
  const [error, setError] = useState<string | null>(null);
  const { isPending, mutate } = useMutation({
    mutationFn: () =>
      openAgentChannel(orgSlug ?? '', tenantSlug, {
        lifetimeSeconds: Number(lifetime),
        maxClass,
        receiverAgentId: receiver,
        senderAgentId: agentId,
        [kind]: scope,
      }),
    onError: (mutationError) => setError(getApiErrorMessage(mutationError, t('openFailed'))),
    onSuccess: onOpened,
  });

  return (
    <Modal
      open
      isPrimaryActionDisabled={!receiver || !scope.trim()}
      isPrimaryActionLoading={isPending}
      onClose={onClose}
      onPrimaryAction={() => mutate()}
      primaryActionLabel={t('open')}
      title={t('openTitle')}
    >
      <div className="flex flex-col gap-4">
        <Select
          containerClassName="mb-0"
          label={t('receiver')}
          onChange={setReceiver}
          options={agents
            .filter((agent) => agent.id !== agentId && agent.status !== 'Revoked')
            .map((agent) => ({ label: agent.name, value: agent.id }))}
          placeholder={t('receiverPlaceholder')}
          value={receiver}
        />
        <Select
          containerClassName="mb-0"
          label={t('kind')}
          onChange={(value) => {
            setKind(value as 'topics' | 'resource');
            setScope(value === 'topics' ? `${topicArea}.>` : '');
          }}
          options={[
            { label: t('kindTopics'), value: 'topics' },
            { label: t('kindResource'), value: 'resource' },
          ]}
          value={kind}
        />
        <Input
          containerClassName="mb-0"
          label={kind === 'topics' ? t('topics') : t('resource')}
          onChange={(event) => setScope(event.target.value)}
          placeholder={kind === 'topics' ? `${topicArea}.tasks` : 'doc:42'}
          value={scope}
        />
        <Select
          containerClassName="mb-0"
          label={t('maxClass')}
          onChange={setMaxClass}
          options={CLASSES.map((level) => ({ label: level, value: level }))}
          value={maxClass}
        />
        <Select
          containerClassName="mb-0"
          label={t('lifetime')}
          onChange={setLifetime}
          options={LIFETIMES.map((option) => ({
            label: t(`lifetimes.${option.key}`),
            value: String(option.seconds),
          }))}
          value={lifetime}
        />
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

/** The channels this agent shares data through, and opening or closing one. */
export function ChannelsSection() {
  const t = useTranslations('dashboard.agentChannels');
  const tErrors = useTranslations('common.errors');
  const { agentId, orgSlug, tenantSlug } = useAgentRouteParams();
  const { hasPermission } = useTenantPermissions();
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [isOpening, setIsOpening] = useState(false);
  const canManage = hasPermission('Agents', 'Delegate');
  const hasOrg = Boolean(orgSlug && tenantSlug);
  const queryKey = ['agent-channels', orgSlug, tenantSlug];
  const { data, error, isLoading } = useQuery({
    enabled: hasOrg,
    queryFn: () => getAgentChannels(orgSlug ?? '', tenantSlug),
    queryKey,
  });
  const { data: agents } = useQuery({
    enabled: hasOrg,
    queryFn: () => getTenantAgents(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-agents', orgSlug, tenantSlug, 'channel-names'],
  });
  const names = new Map((agents ?? []).map((agent) => [agent.id, agent.name]));
  const channels = (data ?? []).filter(
    (channel) => channel.senderAgentId === agentId || channel.receiverAgentId === agentId,
  );
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[26%]', label: t('columns.withAgent') },
    { className: 'w-[30%]', label: t('columns.scope') },
    { className: 'w-[14%]', label: t('columns.maxClass') },
    { className: 'w-[18%]', label: t('columns.ends') },
    { className: 'w-[12%]', label: t('columns.status') },
  ];

  async function refresh() {
    await queryClient.invalidateQueries({ queryKey });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  async function close(channel: AgentChannel) {
    await closeAgentChannel(orgSlug ?? '', tenantSlug, channel.id);
    showNotification({ message: t('closed'), type: 'success' });
    await refresh();
  }

  return (
    <>
      <DashboardDataCard
        actionLabel={canManage ? t('open') : undefined}
        description={t('description')}
        errorMessage={errorMessage}
        title={t('title')}
        onActionClick={canManage ? () => setIsOpening(true) : undefined}
      >
        <DashboardTableShell
          columns={columns}
          emptyMessage={t('empty')}
          hasActionsColumn
          isEmpty={channels.length === 0}
          isLoading={isLoading}
          loadingMessage={t('loading')}
          minWidthClassName="min-w-190"
          onSortChange={() => {}}
        >
          {channels.map((channel) => {
            const isSender = channel.senderAgentId === agentId;
            const otherId = isSender ? channel.receiverAgentId : channel.senderAgentId;

            return (
              <tr key={channel.id} className="group h-11 transition hover:bg-hoverBg">
                <td className="px-4 py-2">
                  <TableCellText className="font-semibold text-white">
                    {names.get(otherId) ?? otherId}
                  </TableCellText>
                  <p className="text-[10px] text-textGray">
                    {isSender ? t('sharesWith') : t('readsFrom')}
                  </p>
                </td>
                <td className="px-4 py-2">
                  <TableCellText className="font-mono">{channel.scope}</TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>{channel.maxClass}</TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>{formatBackendDateTime(channel.expiresAt)}</TableCellText>
                </td>
                <td className="px-4 py-2">
                  <TableCellText>{channel.isOpen ? t('isOpen') : t('isClosed')}</TableCellText>
                </td>
                <DashboardTableActionsCell className="px-4 py-2">
                  <div className="flex justify-end">
                    {canManage && channel.isOpen ? (
                      <DashboardActionsMenu
                        actionLabels={{ Close: t('close') }}
                        actions={['Close']}
                        ariaLabel={t('menu')}
                        getActionErrorMessage={(actionError) =>
                          getApiErrorMessage(actionError, t('closeFailed'))
                        }
                        modalContentByAction={{
                          Close: {
                            description: t('closeDescription'),
                            primaryActionLabel: t('close'),
                            secondaryActionLabel: t('keep'),
                            title: t('closeTitle'),
                          },
                        }}
                        onActionConfirm={() => close(channel)}
                      />
                    ) : null}
                  </div>
                </DashboardTableActionsCell>
              </tr>
            );
          })}
        </DashboardTableShell>
      </DashboardDataCard>

      {isOpening ? (
        <OpenChannelModal
          agentId={agentId}
          agents={agents ?? []}
          onClose={() => setIsOpening(false)}
          onOpened={async () => {
            setIsOpening(false);
            showNotification({ message: t('opened'), type: 'success' });
            await refresh();
          }}
        />
      ) : null}
    </>
  );
}
