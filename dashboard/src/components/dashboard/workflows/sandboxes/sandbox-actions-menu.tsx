'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { Sandbox } from '@/types/sandbox';

export type SandboxAction = 'Open' | 'Archive';

type SandboxActionsMenuProps = {
  canArchive: boolean;
  onAction: (action: SandboxAction) => void;
  onArchive: () => Promise<void>;
  sandbox: Sandbox;
};

/** What a person may do to one sandbox from the list. */
export function SandboxActionsMenu({
  canArchive,
  onAction,
  onArchive,
  sandbox,
}: SandboxActionsMenuProps) {
  const t = useTranslations('dashboard.sandboxes.actions');
  const actions: SandboxAction[] =
    canArchive && sandbox.status !== 'archived' ? ['Open', 'Archive'] : ['Open'];

  return (
    <DashboardActionsMenu
      actionLabels={{ Archive: t('archive'), Open: t('open') }}
      actions={actions}
      ariaLabel={t('menu', { name: sandbox.name })}
      customActions={['Open']}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('archiveFailed'))}
      getActionSuccessMessage={() => t('archived')}
      modalContentByAction={{
        Archive: {
          description: t('archiveDescription', { name: sandbox.name }),
          primaryActionLabel: t('archive'),
          title: t('archiveTitle', { name: sandbox.name }),
        },
      }}
      onActionConfirm={onArchive}
      onCustomAction={onAction}
    />
  );
}
