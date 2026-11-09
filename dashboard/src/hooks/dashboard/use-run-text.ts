import { useTranslations } from 'next-intl';

import type { Approval, ApprovalAction } from '@/types/approval';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { RunAction, RunSummary } from '@/types/run';
import { getRunDisplayId } from '@/utils/run';

/** The confirmation dialogs of the run and approval actions, in the current language. */
export function useRunText() {
  const t = useTranslations('dashboard.agents');

  function runActionModalContent(
    run: Pick<RunSummary, 'id'>,
  ): Partial<Record<RunAction, DashboardActionModalContent>> {
    return {
      'Stop run': {
        title: t('runs.stopModal.title'),
        description: t('runs.stopModal.description', { id: getRunDisplayId(run) }),
        primaryActionLabel: t('runs.stopModal.submit'),
        secondaryActionLabel: t('runs.stopModal.keep'),
        warningNote: t('runs.stopModal.warning'),
        warningTone: 'caution',
      },
    };
  }

  function approvalActionModalContent(
    approval: Approval,
  ): Record<ApprovalAction, DashboardActionModalContent> {
    return {
      Approve: {
        title: t('approvals.actionModals.Approve.title'),
        description: t('approvals.actionModals.Approve.description'),
        primaryActionLabel: t('approvals.actionModals.Approve.submit'),
      },
      Deny: {
        title: t('approvals.actionModals.Deny.title'),
        description: t('approvals.actionModals.Deny.description', { action: approval.action }),
        primaryActionLabel: t('approvals.actionModals.Deny.submit'),
        warningNote: t('approvals.actionModals.Deny.warning'),
        warningTone: 'caution',
      },
    };
  }

  return { approvalActionModalContent, runActionModalContent };
}
