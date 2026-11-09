'use client';

import { useTranslations } from 'next-intl';

import { Button } from '@/components/ui/Button';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import type { SandboxVersion } from '@/types/sandbox';
import { formatBytes } from '@/utils/format-bytes';

type VersionBuildStatusProps = {
  canPin: boolean;
  onPin: (packages: string[]) => void;
  version: SandboxVersion;
};

/** How far building a version got, in words, and what to do about what it found. */
export function VersionBuildStatus({ canPin, onPin, version }: VersionBuildStatusProps) {
  const t = useTranslations('dashboard.sandboxes.build');
  const tFailure = useLooseTranslations('dashboard.sandboxes.build.failures');
  const { build } = version;
  const isImage = version.kind === 'image';

  if (build.status === 'building') {
    return <p className="text-xs text-textGray">{isImage ? t('scanning') : t('building')}</p>;
  }

  if (build.status === 'failed') {
    const failure = build.failure ?? '';
    const reason = tFailure.has(failure) ? tFailure(failure) : failure;

    return (
      <p className="rounded-lg border border-error bg-error/10 px-3 py-2 text-xs text-error">
        {reason}
        {build.detail ? `: ${build.detail}` : ''}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2 text-xs text-textGray">
      {isImage && build.findings ? (
        <p>
          {t('findings', {
            high: build.findings.high,
            low: build.findings.low,
            medium: build.findings.medium,
          })}
        </p>
      ) : null}
      {!isImage && build.digest ? (
        <p className="font-mono break-all">
          {t('readyBundle', {
            digest: build.digest,
            size: build.bytes === null ? '' : formatBytes(build.bytes),
          })}
        </p>
      ) : null}
      {build.unlisted.length > 0 ? (
        <div className="flex flex-col gap-2 rounded-lg bg-orange/10 px-3 py-2 text-orange">
          <p>{t('unlisted', { packages: build.unlisted.join(', ') })}</p>
          {canPin ? (
            <div>
              <Button type="button" variant="outline" onClick={() => onPin(build.unlisted)}>
                {t('pinNext')}
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
