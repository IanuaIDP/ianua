'use client';

import { useTranslations } from 'next-intl';

import { DashboardActionsMenu } from '@/components/dashboard/shared/dashboard-actions-menu';
import type { DashboardActionModalContent } from '@/types/dashboard';
import type { DnsRecord } from '@/types/dns-record';

type DnsRecordAction = 'Delete' | 'Edit';

type DnsRecordActionsMenuProps = {
  canEdit?: boolean;
  record: DnsRecord;
  onDelete: (record: DnsRecord) => void;
  onEdit: (record: DnsRecord) => void;
};

const modalContentByAction: Partial<Record<DnsRecordAction, DashboardActionModalContent>> = {};

export function DnsRecordActionsMenu({
  canEdit = true,
  record,
  onDelete,
  onEdit,
}: DnsRecordActionsMenuProps) {
  const tActions = useTranslations('dashboard.actions');
  const actions: DnsRecordAction[] = canEdit ? ['Edit', 'Delete'] : [];

  return (
    <DashboardActionsMenu
      actions={actions}
      ariaLabel={tActions('openActionsFor', { name: `${record.name} ${record.recordType}` })}
      customActions={actions}
      modalContentByAction={modalContentByAction}
      onCustomAction={(action) => {
        if (action === 'Edit') {
          onEdit(record);
        }

        if (action === 'Delete') {
          onDelete(record);
        }
      }}
    />
  );
}
