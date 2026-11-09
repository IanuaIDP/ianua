'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { RunStatusBadge } from '@/components/dashboard/workflows/workflow-badges';
import type { Execution } from '@/types/workflows';

/** Says how the run shown on the canvas stands. */
export function RunBar({ onClose, run }: { onClose?: () => void; run: Execution }) {
  const t = useTranslations('dashboard.workflowBuilder.runBar');
  const { tenantPathFor } = useBuilderContext();
  const isTest = run.mode === 'test';

  return (
    <div className="flex items-center gap-3 rounded-lg bg-cardBg px-3 py-2 text-xs text-white">
      <span className="font-semibold">{isTest ? t('test') : t('run')}</span>
      <RunStatusBadge status={run.status} />
      {isTest ? <span className="text-textGray">{t('nothingChanged')}</span> : null}
      <Link
        className="ml-auto font-semibold text-primary hover:underline"
        href={tenantPathFor(`workflows/runs/${run.id}`)}
      >
        {t('open')}
      </Link>
      {onClose ? (
        <button type="button" className="text-textGray hover:text-white" onClick={onClose}>
          {t('close')}
        </button>
      ) : null}
    </div>
  );
}
