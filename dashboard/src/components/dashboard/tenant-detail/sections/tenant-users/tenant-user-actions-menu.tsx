'use client';

import { useMemo } from 'react';
import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { createMemberActionModalContent } from '@/components/dashboard/shared/member-action-modal-content';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { getApiErrorMessage } from '@/lib/api';
import { DashboardActionModalContent } from '@/types/dashboard';
import type { TenantUser, TenantUserAction, TenantUserStatus } from '@/types/tenant-user';

type TenantUserActionsMenuProps = {
  canDeactivate?: boolean;
  canDelete?: boolean;
  canUpdate?: boolean;
  /** Offering the fields of a tenant that keeps none would lead nowhere. */
  hasFields?: boolean;
  isSelf?: boolean;
  onActionConfirm: (user: TenantUser, action: TenantUserAction) => Promise<void> | void;
  onEditFieldsClick: (user: TenantUser) => void;
  onResetPasswordClick: (user: TenantUser) => void;
  user: TenantUser;
};

const tenantUserActionsByStatus: Record<TenantUserStatus, TenantUserAction[]> = {
  Active: ['Edit user fields', 'Lock', 'Reset Password', 'Delete Forever'],
  Closing: [],
  Locked: ['Edit user fields', 'Restore Access'],
  Invited: ['Edit user fields', 'Revoke Invitation'],
  PendingVerification: ['Edit user fields', 'Delete Forever'],
  InvitationExpired: ['Edit user fields', 'Resend Invitation', 'Delete Forever'],
  Deactivated: ['Edit user fields', 'Delete Forever'],
};

const instantTenantUserActions: TenantUserAction[] = ['Resend Invitation'];
const customTenantUserActions: TenantUserAction[] = ['Edit user fields', 'Reset Password'];
const deactivateTenantUserActions: TenantUserAction[] = ['Lock', 'Restore Access'];

export function TenantUserActionsMenu({
  canDeactivate = true,
  canDelete = true,
  canUpdate = true,
  hasFields = false,
  isSelf = false,
  onActionConfirm,
  onEditFieldsClick,
  onResetPasswordClick,
  user,
}: TenantUserActionsMenuProps) {
  const t = useTranslations('dashboard.actions');
  const tMember = useLooseTranslations('dashboard.memberActions');
  const tActionLabels = useLooseTranslations('dashboard.actions.labels');
  const tenantUserActionModalContent = useMemo<
    Partial<Record<TenantUserAction, DashboardActionModalContent>>
  >(() => createMemberActionModalContent(tMember, 'user'), [tMember]);
  const availableActions = tenantUserActionsByStatus[user.status].filter((action) => {
    if (action === 'Delete Forever') {
      return canDelete && !isSelf;
    }

    if (action === 'Edit user fields') {
      return hasFields;
    }

    if (deactivateTenantUserActions.includes(action)) {
      return canDeactivate && !isSelf;
    }

    return canUpdate;
  });
  const availableCustomActions = customTenantUserActions.filter((action) =>
    availableActions.includes(action),
  );

  return (
    <DashboardActionsMenu
      actions={availableActions}
      ariaLabel={t('openActionsFor', { name: user.displayName })}
      customActions={availableCustomActions}
      getActionErrorMessage={(error) => getApiErrorMessage(error, tMember('user.updateFailed'))}
      getActionSuccessMessage={(action) => t('completed', { action: tActionLabels(action) })}
      instantActions={instantTenantUserActions}
      modalContentByAction={tenantUserActionModalContent}
      onActionConfirm={(action) => onActionConfirm(user, action)}
      onCustomAction={(action) => {
        if (action === 'Edit user fields') {
          onEditFieldsClick(user);
          return;
        }

        if (action === 'Reset Password') {
          onResetPasswordClick(user);
        }
      }}
    />
  );
}
