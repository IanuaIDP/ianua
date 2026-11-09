'use client';

import { useTranslations } from 'next-intl';

import { DashboardStatusBadge } from '@/components/dashboard/shared/dashboard-status-badge';
import { DashboardTableActionsCell } from '@/components/dashboard/shared/dashboard-table-actions-cell';
import { DashboardTableShell } from '@/components/dashboard/shared/dashboard-table-shell';
import type { DashboardTableColumn } from '@/components/dashboard/shared/dashboard-table-shell';
import { CredentialActionsMenu } from '@/components/dashboard/tenant-detail/sections/agents/credentials/credential-actions-menu';
import { GracePeriodCountdown } from '@/components/dashboard/tenant-detail/sections/agents/credentials/grace-period-countdown';
import type { Credential, CredentialAction } from '@/types/credential';
import { getBadgeSoftColorClass } from '@/utils/badge-colors';
import { cn } from '@/utils/cn';
import { truncatePublicKey } from '@/utils/credential';
import { formatBackendDateTime } from '@/utils/date';

type CredentialsTableProps = {
  canRevoke: boolean;
  canRotate: boolean;
  isLoading?: boolean;
  credentials: Credential[];
  onCredentialAction: (credential: Credential, action: CredentialAction) => Promise<void> | void;
  onRotate: (credential: Credential) => void;
};

export function CredentialsTable({
  canRevoke,
  canRotate,
  isLoading = false,
  credentials,
  onCredentialAction,
  onRotate,
}: CredentialsTableProps) {
  const t = useTranslations('dashboard.credentials');
  const columns: DashboardTableColumn<never>[] = [
    { className: 'w-[70%]', label: t('title') },
    { className: 'w-[30%] right-0 z-20', label: '' },
  ];

  return (
    <DashboardTableShell
      columns={columns}
      isEmpty={credentials.length === 0}
      isLoading={isLoading}
      loadingMessage={t('loading')}
      minWidthClassName="min-w-220"
      onSortChange={() => {}}
    >
      {credentials.map((credential) => {
        const canRotateCredential =
          canRotate && credential.status === 'Active' && !credential.attestation;

        return (
          <tr key={credential.id} className="group transition hover:bg-hoverBg">
            <td className="px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-white">{credential.kid}</span>
                <span
                  className={cn(
                    'inline-flex h-5 items-center rounded-md px-1.5 text-[10px] font-medium leading-none',
                    getBadgeSoftColorClass(credential.algorithm),
                  )}
                >
                  {credential.algorithm}
                </span>
              </div>
              <p className="mt-1 inline-flex items-center gap-1 font-mono text-[10px] text-white">
                <span className="material-symbols-rounded text-xs!" aria-hidden>
                  key
                </span>
                {truncatePublicKey(credential.publicKey)}
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-textGray">
                <span>
                  {t('created')}{' '}
                  <span className="text-white">{formatBackendDateTime(credential.createdAt)}</span>
                </span>
                {credential.attestation ? (
                  <>
                    <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                    <span className="inline-flex items-center gap-1.5">
                      {t('attestedBy')}
                      <span className="inline-flex h-4 items-center rounded px-1 text-[9px] font-semibold uppercase leading-none text-white bg-white/10">
                        {credential.attestation.method}
                      </span>
                      <span className="font-mono text-white">{credential.attestation.subject}</span>
                    </span>
                  </>
                ) : null}
                {credential.status === 'Rotated' && credential.graceEndsAt ? (
                  <>
                    <span className="inline-block h-4 w-px bg-borderGray" aria-hidden />
                    <GracePeriodCountdown graceEndsAt={credential.graceEndsAt} />
                  </>
                ) : null}
              </div>
            </td>
            <DashboardTableActionsCell className="px-4 py-2.5" stopRowClick={false}>
              <div className="flex items-center justify-end gap-3">
                <DashboardStatusBadge status={credential.status} />
                {canRotateCredential ? (
                  <button
                    type="button"
                    onClick={() => onRotate(credential)}
                    className="inline-flex h-7 items-center gap-1.5 rounded-md border border-borderGray px-2.5 text-[10px] font-medium text-white transition hover:bg-hoverBg disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <span className="material-symbols-rounded text-sm!" aria-hidden>
                      sync
                    </span>
                    {t('rotate')}
                  </button>
                ) : null}
                <CredentialActionsMenu
                  canRevoke={canRevoke}
                  credential={credential}
                  onActionConfirm={onCredentialAction}
                />
              </div>
            </DashboardTableActionsCell>
          </tr>
        );
      })}
    </DashboardTableShell>
  );
}
