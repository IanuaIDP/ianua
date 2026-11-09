'use client';

import { useTranslations } from 'next-intl';

import { ToneBadge, type BadgeTone } from '@/components/dashboard/workflows/workflow-badges';

/** Whether a sandbox still takes new versions. */
export function SandboxStatusBadge({ status }: { status: string }) {
  const t = useTranslations('dashboard.sandboxes.status');

  return (
    <ToneBadge tone={status === 'archived' ? 'neutral' : 'ok'}>
      {status === 'archived' ? t('archived') : t('active')}
    </ToneBadge>
  );
}

const buildTones: Record<string, BadgeTone> = {
  building: 'info',
  failed: 'bad',
  ready: 'ok',
};

/** How far building a version's bundle, or scanning its image, got. */
export function BuildStatusBadge({ status }: { status: string }) {
  const t = useTranslations('dashboard.sandboxes.build.status');
  const known = status === 'building' || status === 'failed' || status === 'ready';

  return <ToneBadge tone={buildTones[status] ?? 'neutral'}>{known ? t(status) : status}</ToneBadge>;
}
