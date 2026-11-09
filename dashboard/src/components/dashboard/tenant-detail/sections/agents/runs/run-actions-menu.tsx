'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import { useRunText } from '@/hooks/dashboard/use-run-text';
import { getApiErrorMessage } from '@/lib/api';
import type { RunSummary, RunAction } from '@/types/run';
import { getRunDisplayId } from '@/utils/run';

type RunActionsMenuProps = {
  canStop: boolean;
  canView: boolean;
  run: RunSummary;
  onStopRun: (run: RunSummary) => Promise<void> | void;
  onViewTrace: (run: RunSummary) => void;
};

const ACTIVE_RUN_STATUSES = new Set(['Running', 'AwaitingApproval', 'Halted']);

export function RunActionsMenu({
  canStop,
  canView,
  run,
  onStopRun,
  onViewTrace,
}: RunActionsMenuProps) {
  const t = useTranslations('dashboard.agents.runs');
  const tActions = useTranslations('dashboard.actions');
  const { runActionModalContent } = useRunText();
  const actions: RunAction[] = [
    ...(canView ? (['View trace'] as const) : []),
    ...(canStop && ACTIVE_RUN_STATUSES.has(run.status) ? (['Stop run'] as const) : []),
  ];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: getRunDisplayId(run) })}
      customActions={['View trace']}
      getActionErrorMessage={(error) => getApiErrorMessage(error, t('stopFailed'))}
      getActionSuccessMessage={() => t('stopped')}
      modalContentByAction={runActionModalContent(run)}
      onActionConfirm={(action) => (action === 'Stop run' ? onStopRun(run) : undefined)}
      onCustomAction={(action) => (action === 'View trace' ? onViewTrace(run) : undefined)}
    />
  );
}
