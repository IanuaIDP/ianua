'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { getApiErrorMessage } from '@/lib/api';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { Tool, ToolAction } from '@/types/tool';

type ToolActionsMenuProps = {
  onActionConfirm: (tool: Tool, action: ToolAction) => Promise<void> | void;
  tool: Tool;
};

export function ToolActionsMenu({ onActionConfirm, tool }: ToolActionsMenuProps) {
  const t = useTranslations('dashboard.tools');
  const tActions = useTranslations('dashboard.actions');
  const toolActionModalContent: Record<ToolAction, DashboardActionModalContent> = {
    'Enable tool': {
      title: t('actionModals.enable.title'),
      description: t('actionModals.enable.description'),
      primaryActionLabel: t('actionModals.enable.submit'),
    },
    'Disable tool': {
      title: t('actionModals.disable.title'),
      description: t('actionModals.disable.description'),
      primaryActionLabel: t('actionModals.disable.submit'),
    },
    Delete: {
      title: t('actionModals.delete.title'),
      description: t('actionModals.delete.description'),
      primaryActionLabel: t('actionModals.delete.submit'),
      warningTone: 'danger',
    },
  };
  const { hasPermission } = useTenantPermissions();
  const actions: ToolAction[] = !hasPermission('Agents', 'Manage')
    ? []
    : tool.status === 'Disabled'
      ? ['Enable tool', 'Delete']
      : ['Disable tool'];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: tool.name })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        t(
          action === 'Delete'
            ? 'toasts.deleted'
            : action === 'Enable tool'
              ? 'toasts.enabled'
              : 'toasts.disabled',
        )
      }
      modalContentByAction={toolActionModalContent}
      onActionConfirm={(action) => onActionConfirm(tool, action)}
    />
  );
}
