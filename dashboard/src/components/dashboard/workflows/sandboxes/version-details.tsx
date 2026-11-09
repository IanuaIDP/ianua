'use client';

import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { CodeEditor } from '@/components/dashboard/workflows/sandboxes/code-editor-loader';
import { BuildStatusBadge } from '@/components/dashboard/workflows/sandboxes/sandbox-badges';
import { TrialPanel } from '@/components/dashboard/workflows/sandboxes/trial-panel';
import { VersionBuildStatus } from '@/components/dashboard/workflows/sandboxes/version-build-status';
import { ToneBadge } from '@/components/dashboard/workflows/workflow-badges';
import { Button } from '@/components/ui/Button';
import { useWorkflowCaller } from '@/hooks/dashboard/use-workflow-caller';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import { getSandboxRuntimes } from '@/lib/api';
import type { Sandbox, SandboxVersion, WrittenSandboxCode } from '@/types/sandbox';
import { formatBackendDateTime } from '@/utils/date';
import { formatBytes } from '@/utils/format-bytes';
import { amountFromMicros } from '@/utils/micros';
import { getActorWord } from '@/utils/workflow-actor';

type VersionDetailsProps = {
  canUpdate: boolean;
  onFixed: (written: WrittenSandboxCode) => void;
  onPin: (packages: string[]) => void;
  onPush: () => void;
  sandbox: Sandbox;
  version: SandboxVersion;
};

/** One saved version: what it runs, how its build went, and trying it. */
export function VersionDetails({
  canUpdate,
  onFixed,
  onPin,
  onPush,
  sandbox,
  version,
}: VersionDetailsProps) {
  const t = useTranslations('dashboard.sandboxes.version');
  const tActor = useTranslations('dashboard.workflows.actor');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const caller = useWorkflowCaller();
  const { data: runtimes } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug) && version.kind === 'code',
    queryFn: () => getSandboxRuntimes(orgSlug ?? '', tenantSlug),
    queryKey: ['sandbox-runtimes', orgSlug, tenantSlug],
  });
  const isActive = sandbox.status !== 'archived';
  const isRetired =
    Boolean(runtimes && version.runtime) &&
    !runtimes?.some((runtime) => runtime.runtime === version.runtime);
  const canTry = canUpdate && isActive && version.build.status === 'ready';
  const canPush = canUpdate && version.kind === 'code' && Boolean(version.code);

  return (
    <section className="rounded-lg border border-borderGray bg-cardBg p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-base font-bold text-white">
            {t('heading', { number: version.number })}
          </h2>
          <BuildStatusBadge status={version.build.status} />
          {isRetired ? <ToneBadge tone="warn">{t('retired')}</ToneBadge> : null}
          {version.agent ? <ToneBadge tone="info">{t('holdsAgent')}</ToneBadge> : null}
        </div>
        {canPush ? (
          <Button type="button" variant="outline" onClick={onPush}>
            {t('push')}
          </Button>
        ) : null}
      </div>

      <div className="mt-3">
        <VersionBuildStatus canPin={canUpdate && isActive} version={version} onPin={onPin} />
      </div>

      <dl className="mt-4 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="text-textGray">{version.kind === 'image' ? t('image') : t('runtime')}</dt>
          <dd className="break-all text-white">
            {version.kind === 'image' ? version.image : (version.runtime ?? version.image)}
          </dd>
        </div>
        <div>
          <dt className="text-textGray">{t('limits')}</dt>
          <dd className="text-white">
            {t('limitsValue', { memory: version.memoryMib, seconds: version.runSeconds })}
          </dd>
        </div>
        <div>
          <dt className="text-textGray">{t('saved')}</dt>
          <dd className="text-white">
            {t('savedValue', {
              at: formatBackendDateTime(version.createdAt),
              who: tActor(getActorWord(version.savedBy, caller)),
            })}
          </dd>
        </div>
        <div>
          <dt className="text-textGray">{t('hosts')}</dt>
          <dd className="break-all text-white">
            {version.allowedHosts.length > 0 ? version.allowedHosts.join(', ') : t('noNetwork')}
          </dd>
        </div>
        {version.imageBytes !== null ? (
          <div>
            <dt className="text-textGray">{t('imageSize')}</dt>
            <dd className="text-white">{formatBytes(version.imageBytes)}</dd>
          </div>
        ) : null}
        {version.importedFrom ? (
          <div className="sm:col-span-2">
            <dt className="text-textGray">{t('importedFrom')}</dt>
            <dd className="break-all text-white">
              {t('importedValue', {
                commit: version.importedFrom.commit.slice(0, 12),
                path: version.importedFrom.path,
                repository: version.importedFrom.repository,
              })}
            </dd>
          </div>
        ) : null}
        {version.packages.length > 0 ? (
          <div className="sm:col-span-2">
            <dt className="mb-1 text-textGray">{t('packages')}</dt>
            <dd className="flex flex-wrap gap-1.5">
              {version.packages.map((item) => (
                <span
                  key={item.name}
                  className="rounded-md bg-white/15 px-1.5 py-0.5 text-[10px] font-medium text-white"
                >
                  {item.name} {item.version}
                </span>
              ))}
            </dd>
          </div>
        ) : null}
        {version.agent ? (
          <div className="sm:col-span-2">
            <dt className="text-textGray">{t('agentGoal')}</dt>
            <dd className="text-white">{version.agent.goal}</dd>
            <dd className="mt-1 text-textGray">
              {t('agentRules', {
                cap: amountFromMicros(version.agent.spendCapMicros),
                steps: version.agent.maxSteps,
                tries: version.agent.tries,
              })}
            </dd>
          </div>
        ) : null}
      </dl>

      {version.code ? (
        <div className="mt-4">
          <p className="mb-2 text-xs font-semibold text-textGray">{t('code')}</p>
          <CodeEditor
            ariaLabel={t('code')}
            language={sandbox.language ?? 'python'}
            readOnly
            value={version.code}
          />
        </div>
      ) : null}

      {canTry ? (
        <TrialPanel key={version.id} sandboxId={sandbox.id} version={version} onFixed={onFixed} />
      ) : null}
    </section>
  );
}
