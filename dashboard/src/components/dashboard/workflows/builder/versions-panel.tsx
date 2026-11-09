'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { SmallButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import { useNotification } from '@/components/ui/notifications';
import { Modal } from '@/components/ui/modal';
import { archiveWorkflowVersion, getApiErrorMessage, getBuilderWorkflow } from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { formatBackendDateTime } from '@/utils/date';
import { cn } from '@/utils/cn';

const VERSIONS_SHOWN = 20;

type VersionsPanelProps = {
  canDelete: boolean;
  latestVersion: number;
  openVersion: number | null;
  workflowId: string;
  onChanged: () => void;
};

/** Walks down from the latest number, since the API has no list of a workflow's versions. */
export function VersionsPanel({
  canDelete,
  latestVersion,
  onChanged,
  openVersion,
  workflowId,
}: VersionsPanelProps) {
  const t = useTranslations('dashboard.workflowBuilder.versions');
  const tStatus = useLooseTranslations('dashboard.workflowBuilder.status');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const { orgSlug, tenantPathFor, tenantSlug } = useBuilderContext();
  const [toArchive, setToArchive] = useState<number | null>(null);
  const numbers = Array.from(
    { length: Math.min(latestVersion, VERSIONS_SHOWN) },
    (_, index) => latestVersion - index,
  );
  const versions = useQueries({
    queries: numbers.map((number) => ({
      enabled: Boolean(orgSlug),
      queryFn: () => getBuilderWorkflow(orgSlug ?? '', tenantSlug, workflowId, number),
      queryKey: ['workflow-version', orgSlug, tenantSlug, workflowId, number],
    })),
  });

  const { isPending: isArchiving, mutate: submitArchive } = useMutation({
    mutationFn: (version: number) =>
      archiveWorkflowVersion(orgSlug ?? '', tenantSlug, workflowId, version),
    onError: (error) => {
      setToArchive(null);
      showNotification({
        message: getApiErrorMessage(error, t('archiveFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setToArchive(null);
      showNotification({ message: t('archived'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['workflow-version', orgSlug, tenantSlug, workflowId],
      });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onChanged();
    },
  });

  return (
    <div className="flex-1 overflow-auto p-4">
      <p className="text-base font-bold text-white">{t('title')}</p>
      <p className="mt-2 text-xs text-textGray">{t('help', { count: VERSIONS_SHOWN })}</p>

      <ul className="mt-3 flex flex-col gap-1">
        {numbers.map((number, index) => {
          const version = versions[index]?.data;
          const isOpen =
            openVersion === number || (openVersion === null && number === latestVersion);

          return (
            <li
              key={number}
              className={cn(
                'flex items-center justify-between gap-2 rounded-lg px-3 py-2',
                isOpen ? 'bg-primary/15' : 'bg-surfaceInset',
              )}
            >
              <Link
                href={`${tenantPathFor(`workflows/${workflowId}`)}?version=${number}`}
                className="min-w-0 flex-1"
              >
                <p className={cn('text-sm font-semibold', isOpen ? 'text-primary' : 'text-white')}>
                  {t('number', { number })}
                  {version ? ` · ${tStatus(version.status)}` : ''}
                </p>
                <p className="truncate text-xs text-textGray">
                  {version ? formatBackendDateTime(version.updatedAt) : t('loading')}
                </p>
              </Link>
              {canDelete && version && version.status !== 'archived' ? (
                <SmallButton
                  onClick={() => setToArchive(number)}
                  aria-label={t('archive', { number })}
                  icon="inventory_2"
                >
                  {t('archiveShort')}
                </SmallButton>
              ) : null}
            </li>
          );
        })}
      </ul>

      <Modal
        open={toArchive !== null}
        onClose={() => setToArchive(null)}
        title={t('archiveTitle', { number: toArchive ?? 0 })}
        description={t('archiveDescription')}
        primaryActionLabel={t('archiveConfirm')}
        onPrimaryAction={() => {
          if (toArchive !== null) {
            submitArchive(toArchive);
          }
        }}
        isPrimaryActionLoading={isArchiving}
      >
        {null}
      </Modal>
    </div>
  );
}
