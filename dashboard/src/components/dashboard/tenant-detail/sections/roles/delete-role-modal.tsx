'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { getTenantRoles } from '@/lib/api';
import type { Role } from '@/types/role';

type DeleteRoleModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onConfirm: (role: Role, reassignToRoleId?: string) => void;
  orgSlug?: string;
  role: Role | null;
  tenantSlug: string;
};

export function DeleteRoleModal({
  isSubmitting = false,
  onClose,
  onConfirm,
  orgSlug,
  role,
  tenantSlug,
}: DeleteRoleModalProps) {
  const t = useTranslations('dashboard.tenantRoles.deleteModal');
  const open = Boolean(role);
  const hasAssignedUsers = Boolean(role && role.assignedUserCount > 0);
  const [wasOpen, setWasOpen] = useState(open);
  const [reassignToRoleId, setReassignToRoleId] = useState('');

  const { data: roles = [] } = useQuery({
    enabled: open && hasAssignedUsers && Boolean(orgSlug && tenantSlug),
    queryFn: async () => {
      const response = await getTenantRoles(orgSlug ?? '', tenantSlug, { limit: 100 });

      return response.items;
    },
    queryKey: ['tenant-roles', orgSlug, tenantSlug, 'options'],
  });
  const reassignRoleOptions = roles
    .filter((candidate) => candidate.id !== role?.id)
    .map((candidate) => ({ label: candidate.name, value: candidate.id }));
  const defaultReassignOption =
    reassignRoleOptions.find((option) => option.label.trim().toLowerCase() === 'member') ??
    reassignRoleOptions[0];
  const selectedReassignToRoleId = reassignToRoleId || (defaultReassignOption?.value ?? '');

  if (open !== wasOpen) {
    setWasOpen(open);

    if (!open) {
      setReassignToRoleId('');
    }
  }

  function handleClose() {
    if (isSubmitting) {
      return;
    }

    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      onPrimaryAction={() => {
        if (role) {
          onConfirm(role, hasAssignedUsers ? selectedReassignToRoleId : undefined);
        }
      }}
      isPrimaryActionDisabled={(hasAssignedUsers && !selectedReassignToRoleId) || isSubmitting}
      isPrimaryActionLoading={isSubmitting}
    >
      {hasAssignedUsers ? (
        <>
          <div className="flex items-start gap-2 rounded-lg border border-orange/50 bg-orange/10 p-2.5 text-[10px] font-medium text-orange">
            <span className="material-symbols-rounded text-sm! shrink-0">warning</span>
            {t('reassignNotice', { count: role?.assignedUserCount ?? 0 })}
          </div>

          <Select
            label={t('assignTo')}
            placeholder={reassignRoleOptions.length > 0 ? t('selectRoles') : t('noOtherRoles')}
            containerClassName="mb-0"
            className="bg-cardBg"
            options={reassignRoleOptions}
            value={selectedReassignToRoleId}
            onChange={setReassignToRoleId}
          />
        </>
      ) : null}
    </Modal>
  );
}
