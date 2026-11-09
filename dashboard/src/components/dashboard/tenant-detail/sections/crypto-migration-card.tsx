'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { CRYPTO_MIGRATION_ACTIONS_BY_STATUS } from '@/constants/crypto';
import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { MigrationKeyValue } from '@/components/dashboard/tenant-detail/sections/crypto/migration-key-value';
import { PlanCryptoMigrationModal } from '@/components/dashboard/tenant-detail/sections/crypto/plan-crypto-migration-modal';
import { RollbackCryptoMigrationModal } from '@/components/dashboard/tenant-detail/sections/crypto/rollback-crypto-migration-modal';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useCopyToClipboard } from '@/hooks/dashboard/use-copy-to-clipboard';
import { useTenantPermissions } from '@/hooks/tenants/use-tenant-permissions';
import { useTenantRouteParams } from '@/hooks/tenants/use-tenant-route-params';
import {
  deriveErrorMessage,
  executeTenantCryptoMigrationAction,
  getApiErrorMessage,
  getTenantCryptoKeys,
  getTenantCryptoMigration,
  planTenantCryptoMigration,
  rollbackTenantCryptoMigration,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type {
  PlanCryptoMigrationInput,
  RollbackCryptoMigrationInput,
} from '@/schemas/crypto-schemas';
import type { CryptoMigrationAction } from '@/types/crypto';
import { getCryptoMigrationActionClassName } from '@/utils/crypto';

export function CryptoMigrationCard() {
  const t = useTranslations('dashboard.crypto.migration');
  const tCrypto = useTranslations('dashboard.crypto');
  const tErrors = useTranslations('common.errors');
  const { orgSlug, tenantSlug } = useTenantRouteParams();
  const { canView, hasPermission, isLoading: isLoadingPermissions } = useTenantPermissions();
  const canViewCrypto = canView('Crypto');
  const canUpdateCrypto = hasPermission('Crypto', 'Update');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const copy = useCopyToClipboard();
  const [isPlanModalOpen, setIsPlanModalOpen] = useState(false);
  const [isRollbackModalOpen, setIsRollbackModalOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<Exclude<
    CryptoMigrationAction,
    'Rollback'
  > | null>(null);

  const {
    data: migration,
    error,
    isLoading,
  } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && canViewCrypto),
    queryFn: () => getTenantCryptoMigration(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-crypto-migration', orgSlug, tenantSlug],
  });
  const { data: keys } = useQuery({
    enabled: Boolean(orgSlug && tenantSlug && canViewCrypto && !migration),
    queryFn: () => getTenantCryptoKeys(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
  });
  const activeKeyAlgorithm = keys?.find((key) => key.status === 'Active')?.algorithm;
  const actions =
    migration && canUpdateCrypto
      ? (CRYPTO_MIGRATION_ACTIONS_BY_STATUS[migration.status] ?? [])
      : [];
  const errorMessage = deriveErrorMessage(
    [!orgSlug, tErrors('organizationMissing')],
    [!isLoadingPermissions && !canViewCrypto, t('noPermission')],
    [error, getApiErrorMessage(error, t('loadFailed'))],
  );

  const { isPending: isExecutingAction, mutate: executeAction } = useMutation({
    mutationFn: (action: CryptoMigrationAction) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return executeTenantCryptoMigrationAction(orgSlug, tenantSlug, action);
    },
    onSuccess: async (_, action) => {
      setPendingAction(null);
      showNotification({
        message: t(`actionSuccess.${action}`),
        type: 'success',
      });
      await invalidateCryptoData();
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.updateFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isPlanningMigration, mutate: submitPlanMigration } = useMutation({
    mutationFn: (payload: PlanCryptoMigrationInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return planTenantCryptoMigration(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsPlanModalOpen(false);
      showNotification({ message: t('toasts.planned'), type: 'success' });
      await invalidateCryptoData();
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.planFailed')),
        type: 'error',
      });
    },
  });

  const { isPending: isRollingBackMigration, mutate: submitRollbackMigration } = useMutation({
    mutationFn: (payload: RollbackCryptoMigrationInput) => {
      if (!orgSlug) {
        throw new Error(tErrors('organizationMissing'));
      }

      return rollbackTenantCryptoMigration(orgSlug, tenantSlug, payload);
    },
    onSuccess: async () => {
      setIsRollbackModalOpen(false);
      showNotification({ message: t('toasts.rolledBack'), type: 'success' });
      await invalidateCryptoData();
      await invalidateAuditLogQueries(queryClient, orgSlug);
    },
    onError: (mutationError) => {
      showNotification({
        message: getApiErrorMessage(mutationError, t('toasts.rollbackFailed')),
        type: 'error',
      });
    },
  });

  async function copyKeyId(keyId: string) {
    await copy(keyId, tCrypto('keyIdCopied'));
  }

  async function invalidateCryptoData() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-crypto-migration', orgSlug, tenantSlug],
    });
    await queryClient.invalidateQueries({
      queryKey: ['tenant-crypto-keys', orgSlug, tenantSlug],
    });
  }

  return (
    <>
      <section className="mx-auto flex w-full max-w-360 flex-col overflow-hidden rounded-lg border border-borderGray bg-cardBg">
        <div className="flex shrink-0 flex-col gap-5 px-4 pb-5 pt-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="text-base font-bold leading-tight text-white">{t('title')}</h2>
            <p className="mt-2.5 text-xs font-medium text-textGray">{t('description')}</p>
          </div>

          {actions.length > 0 || (!migration && canUpdateCrypto && canViewCrypto) ? (
            <div className="flex flex-wrap items-center gap-2.5 sm:self-start">
              {!migration && canUpdateCrypto && canViewCrypto ? (
                <button
                  type="button"
                  onClick={() => setIsPlanModalOpen(true)}
                  className={getCryptoMigrationActionClassName('Start')}
                >
                  {t('plan')}
                </button>
              ) : null}
              {actions.map((action) => (
                <button
                  key={action}
                  type="button"
                  disabled={isExecutingAction}
                  onClick={() =>
                    action === 'Rollback' ? setIsRollbackModalOpen(true) : setPendingAction(action)
                  }
                  className={getCryptoMigrationActionClassName(action)}
                >
                  {action === 'Start' ? (
                    <span className="material-symbols-rounded text-base!" aria-hidden="true">
                      play_circle
                    </span>
                  ) : null}
                  {t(`actionLabels.${action}`)}
                </button>
              ))}
            </div>
          ) : null}
        </div>

        {errorMessage ? (
          <div className="mx-4 mb-5 rounded-lg border border-error bg-error/10 px-3 py-2 text-xs font-medium text-error">
            {errorMessage}
          </div>
        ) : null}

        {isLoading || isLoadingPermissions ? (
          <p className="px-4 pb-5 text-xs font-medium text-textGray">{t('loading')}</p>
        ) : migration ? (
          <div className="mx-4 mb-4 grid overflow-hidden rounded-lg border border-borderGray md:grid-cols-3">
            <div className="flex h-full min-w-0 items-center justify-between border-b border-borderGray p-4 md:border-b-0 md:border-r">
              <div className="min-w-0 flex flex-col gap-0.75">
                <span className="text-[10px] font-semibold text-textGray">
                  {t('algorithmMigration')}
                </span>
                <div className="mt-0.75 flex min-w-0 items-center gap-1.5">
                  <span className="rounded-md bg-surfaceChip px-2 py-0.5 text-[10px] font-medium text-white">
                    {migration.sourceAlgorithm}
                  </span>
                  <span className="material-symbols-rounded text-sm text-textGray" aria-hidden>
                    arrow_forward
                  </span>
                  <span className="rounded-md bg-surfaceChip px-2 py-0.5 text-[10px] font-medium text-white">
                    {migration.targetAlgorithm}
                  </span>
                </div>
              </div>
              <DashboardStatusBadge status={migration.status} />
            </div>

            <div className="min-w-0 border-b border-borderGray md:border-b-0 md:border-r">
              <MigrationKeyValue
                label={t('sourceKeyId')}
                value={migration.sourceKeyId}
                onCopy={() => void copyKeyId(migration.sourceKeyId)}
              />
            </div>
            <div className="min-w-0">
              <MigrationKeyValue
                label={t('targetKeyId')}
                value={migration.targetKeyId ?? t('notAvailable')}
                onCopy={
                  migration.targetKeyId
                    ? () => void copyKeyId(migration.targetKeyId ?? '')
                    : undefined
                }
              />
            </div>
          </div>
        ) : (
          <p className="px-4 pb-5 text-xs font-medium text-textGray">{t('none')}</p>
        )}
      </section>

      <PlanCryptoMigrationModal
        excludedAlgorithm={activeKeyAlgorithm}
        isSubmitting={isPlanningMigration}
        open={isPlanModalOpen}
        onClose={() => setIsPlanModalOpen(false)}
        onSubmit={submitPlanMigration}
      />
      <RollbackCryptoMigrationModal
        isSubmitting={isRollingBackMigration}
        open={isRollbackModalOpen}
        onClose={() => setIsRollbackModalOpen(false)}
        onSubmit={submitRollbackMigration}
      />
      <Modal
        open={Boolean(pendingAction)}
        onClose={() => {
          if (!isExecutingAction) {
            setPendingAction(null);
          }
        }}
        title={pendingAction ? t(`actionLabels.${pendingAction}`) : undefined}
        description={pendingAction ? t(`actionConfirm.${pendingAction}`) : undefined}
        showCloseButton={false}
        primaryActionLabel={pendingAction ? t(`actionLabels.${pendingAction}`) : undefined}
        onPrimaryAction={() => {
          if (pendingAction) {
            executeAction(pendingAction);
          }
        }}
        isPrimaryActionLoading={isExecutingAction}
        isPrimaryActionDisabled={isExecutingAction}
      >
        {null}
      </Modal>
    </>
  );
}
