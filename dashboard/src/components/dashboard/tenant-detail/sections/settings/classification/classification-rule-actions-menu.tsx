'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { getApiErrorMessage } from '@/lib/api';
import type { ClassificationRule, ClassificationRuleAction } from '@/types/classification';
import type { DashboardActionModalContent } from '@/types/dashboard';

type ClassificationRuleActionsMenuProps = {
  onRemoveConfirm: (rule: ClassificationRule) => Promise<void> | void;
  rule: ClassificationRule;
};

export function ClassificationRuleActionsMenu({
  onRemoveConfirm,
  rule,
}: ClassificationRuleActionsMenuProps) {
  const t = useTranslations('dashboard.tenantSettings.classification');
  const tActions = useTranslations('dashboard.actions');
  const modalContentByAction: Partial<
    Record<ClassificationRuleAction, DashboardActionModalContent>
  > = {
    Remove: {
      title: t('remove.title'),
      description: t('remove.description', { field: rule.fieldPath }),
      primaryActionLabel: t('remove.submit'),
      warningNote: t('remove.warning'),
      warningTone: 'danger',
    },
  };

  return (
    <DashboardActionsMenu
      actions={['Remove']}
      ariaLabel={tActions('openActionsFor', { name: rule.fieldPath })}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('remove.failed'))}
      getActionSuccessMessage={() => t('remove.done')}
      modalContentByAction={modalContentByAction}
      onActionConfirm={() => onRemoveConfirm(rule)}
    />
  );
}
