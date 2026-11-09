'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useStreamActionModalContent } from '@/hooks/dashboard/use-stream-action-modal-content';
import { getApiErrorMessage } from '@/lib/api';
import type { Stream, StreamAction, StreamStatus } from '@/types/stream';

const streamActionsByStatus: Record<StreamStatus, StreamAction[]> = {
  Active: ['Edit', 'Pause', 'Disable'],
  Paused: ['Edit', 'Resume', 'Disable'],
  Disabled: ['Delete'],
};

const customStreamActions: StreamAction[] = ['Edit'];
const updateStreamActions: StreamAction[] = ['Edit', 'Pause', 'Resume', 'Disable'];

type StreamActionsMenuProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  excludeActions?: StreamAction[];
  onActionConfirm: (stream: Stream, action: StreamAction) => Promise<void> | void;
  onEditClick: (stream: Stream) => void;
  stream: Stream;
};

export function StreamActionsMenu({
  canDelete = true,
  canUpdate = true,
  excludeActions,
  onActionConfirm,
  onEditClick,
  stream,
}: StreamActionsMenuProps) {
  const t = useTranslations('dashboard.streams');
  const tActions = useTranslations('dashboard.actions');
  const modalContentByAction = useStreamActionModalContent();
  const availableActions = streamActionsByStatus[stream.status].filter((action) => {
    if (excludeActions?.includes(action)) {
      return false;
    }

    if (action === 'Delete') {
      return canDelete;
    }

    if (updateStreamActions.includes(action)) {
      return canUpdate;
    }

    return true;
  });
  const availableCustomActions = customStreamActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={tActions('openActionsFor', { name: stream.endpoint })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('toasts.updateFailed'))}
      getActionSuccessMessage={(action) =>
        action === 'Edit' ? tActions('succeeded') : t(`actionSuccess.${action}`)
      }
      modalContentByAction={modalContentByAction}
      onActionConfirm={(action) => onActionConfirm(stream, action)}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEditClick(stream);
        }
      }}
    />
  );
}
