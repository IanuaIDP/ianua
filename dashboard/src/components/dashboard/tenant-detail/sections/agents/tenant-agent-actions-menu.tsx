'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useAgentText } from '@/hooks/dashboard/use-agent-text';
import { getApiErrorMessage } from '@/lib/api';
import type { TenantAgent, TenantAgentAction, TenantAgentStatus } from '@/types/tenant-agent';

// Delete is offered only once revoked, because that is the only time the API
// accepts it: revoking is what stops the agent, and deleting is what forgets
// it. A revoked agent used to be a dead end — nothing further was on offer, so
// the row stayed in the table with no way to clear it.
const agentActionsByStatus: Record<TenantAgentStatus, TenantAgentAction[]> = {
  Active: ['Edit', 'Suspend', 'Revoke'],
  Suspended: ['Edit', 'Resume', 'Revoke'],
  Revoked: ['Edit', 'Delete'],
};

const customAgentActions: TenantAgentAction[] = ['Edit'];
const instantAgentActions: TenantAgentAction[] = ['Resume'];

type TenantAgentActionsMenuProps = {
  agent: TenantAgent;
  canDelete?: boolean;
  canUpdate?: boolean;
  onActionConfirm: (agent: TenantAgent, action: TenantAgentAction) => Promise<void> | void;
  onEditClick: (agent: TenantAgent) => void;
};

export function TenantAgentActionsMenu({
  agent,
  canDelete = true,
  canUpdate = true,
  onActionConfirm,
  onEditClick,
}: TenantAgentActionsMenuProps) {
  const t = useTranslations('dashboard.agents');
  const tActions = useTranslations('dashboard.actions');
  const { actionModalContent } = useAgentText();
  const availableActions = agentActionsByStatus[agent.status].filter((action) => {
    if (action === 'Revoke' || action === 'Delete') {
      return canDelete;
    }

    return canUpdate;
  });
  const availableCustomActions = customAgentActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: agent.name })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        action === 'Edit' ? tActions('succeeded') : t(`actionSuccess.${action}`)
      }
      instantActions={instantAgentActions}
      modalContentByAction={actionModalContent(agent)}
      onActionConfirm={(action) => onActionConfirm(agent, action)}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(agent);
        }
      }}
    />
  );
}
