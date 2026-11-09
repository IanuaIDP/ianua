'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useRunText } from '@/hooks/dashboard/use-run-text';
import { getApiErrorMessage } from '@/lib/api';
import type { Approval, ApprovalAction } from '@/types/approval';

type ApprovalActionsMenuProps = {
  approval: Approval;
  onApprove: (approval: Approval) => Promise<void> | void;
  onDeny: (approval: Approval) => Promise<void> | void;
};

const actions: ApprovalAction[] = ['Approve', 'Deny'];

export function ApprovalActionsMenu({ approval, onApprove, onDeny }: ApprovalActionsMenuProps) {
  const t = useTranslations('dashboard.agents.approvals.menu');
  const { approvalActionModalContent } = useRunText();

  return (
    <DashboardActionsMenu
      actionIcons={{
        Approve: { icon: 'check', className: 'text-primary' },
        Deny: { icon: 'close', className: 'text-error' },
      }}
      actions={actions}
      ariaLabel={t('ariaLabel', { action: approval.action })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('failed'))}
      getActionSuccessMessage={(action) => (action === 'Approve' ? t('approved') : t('denied'))}
      modalContentByAction={approvalActionModalContent(approval)}
      triggerLabel={t('trigger')}
      onActionConfirm={(action) => (action === 'Approve' ? onApprove(approval) : onDeny(approval))}
    />
  );
}
