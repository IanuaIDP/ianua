'use client';

import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { TRIGGER_KEY } from '@/components/dashboard/workflows/builder/constants';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { findStep } from '@/components/dashboard/workflows/builder/working-copy';
import type { WorkflowEdge } from '@/types/workflow-graph';

/** What one arrow means, and the actions on it. */
export function WirePanel({ edge, isImplied }: { edge: WorkflowEdge; isImplied: boolean }) {
  const t = useTranslations('dashboard.workflowBuilder.wire');
  const copy = useWorkingCopy((state) => state.copy);
  const editable = useWorkingCopy((state) => state.editable);
  const disconnect = useWorkingCopy((state) => state.disconnect);
  const openDrawer = useWorkingCopy((state) => state.openDrawer);
  const nameOf = (key: string) =>
    key === TRIGGER_KEY ? t('theTrigger') : (findStep(copy.nodes, key)?.name ?? key);
  const others = copy.edges
    .filter((other) => other.to === edge.to && other.from !== edge.from)
    .map((other) => nameOf(other.from));
  const to = nameOf(edge.to);
  const from = nameOf(edge.from);

  return (
    <div className="flex-1 overflow-auto p-4">
      <p className="text-base font-bold text-white">{t('title')}</p>
      {editable ? (
        <div className="mt-3 flex flex-wrap gap-2">
          <SmallButton
            icon="add"
            onClick={() => openDrawer({ after: edge.from, port: edge.port, to: edge.to })}
          >
            {t('addOnArrow')}
          </SmallButton>
          {!isImplied ? (
            <SmallButton icon="delete" onClick={() => disconnect(edge)}>
              {t('remove')}
            </SmallButton>
          ) : null}
        </div>
      ) : null}
      <p className="mt-4 text-sm text-white">
        {edge.port === 'when_true'
          ? t('startsAfterYes', { from, to })
          : edge.port === 'when_false'
            ? t('startsAfterNo', { from, to })
            : isImplied
              ? t('startsFirst', { to })
              : t('startsAfter', { from, to })}
      </p>
      {!isImplied ? <p className="mt-2 text-sm text-textGray">{t('canUse', { from })}</p> : null}
      {others.length > 0 ? (
        <p className="mt-2 text-sm text-textGray">{t('alsoWaits', { names: others.join(', ') })}</p>
      ) : null}
    </div>
  );
}
