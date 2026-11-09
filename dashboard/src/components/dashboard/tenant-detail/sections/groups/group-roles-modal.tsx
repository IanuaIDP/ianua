'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import {
  fieldClassName,
  fieldContainerClassName,
} from '@/components/dashboard/tenant-detail/sections/form-field-styles';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { Select } from '@/components/ui/Select';
import { assignGroupRole, getApiErrorMessage, getTenantRoles, unassignGroupRole } from '@/lib/api';
import type { Group } from '@/types/group';

type GroupRolesModalProps = {
  group: Group | null;
  onClose: () => void;
  onChanged: () => Promise<void> | void;
  orgSlug?: string;
  tenantSlug: string;
};

export function GroupRolesModal({
  group,
  onChanged,
  onClose,
  orgSlug,
  tenantSlug,
}: GroupRolesModalProps) {
  const t = useTranslations('dashboard.groups.roles');
  const tErrors = useTranslations('common.errors');
  const open = Boolean(group);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [wasOpen, setWasOpen] = useState(open);
  const [selectedRoleId, setSelectedRoleId] = useState('');
  const [pendingRemoval, setPendingRemoval] = useState<{ id: string; name: string } | null>(null);

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      setSelectedRoleId('');
    }
  }

  const { data: roles = [] } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: async () => {
      const response = await getTenantRoles(orgSlug ?? '', tenantSlug, { limit: 100 });

      return response.items;
    },
    queryKey: ['tenant-roles', orgSlug, tenantSlug, 'group-role-options'],
  });

  async function invalidateGroups() {
    await queryClient.invalidateQueries({ queryKey: ['tenant-groups', orgSlug, tenantSlug] });
    await onChanged();
  }

  const { isPending: isAssigning, mutate: submitAssignRole } = useMutation({
    mutationFn: (roleId: string) => {
      if (!orgSlug || !group) {
        throw new Error(tErrors('organizationMissing'));
      }

      return assignGroupRole(orgSlug, tenantSlug, group.id, roleId);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('bindFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setSelectedRoleId('');
      showNotification({ message: t('bound'), type: 'success' });
      await invalidateGroups();
    },
  });

  const { isPending: isUnassigning, mutate: submitUnassignRole } = useMutation({
    mutationFn: (roleId: string) => {
      if (!orgSlug || !group) {
        throw new Error(tErrors('organizationMissing'));
      }

      return unassignGroupRole(orgSlug, tenantSlug, group.id, roleId);
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('removeFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setPendingRemoval(null);
      showNotification({ message: t('removed'), type: 'success' });
      await invalidateGroups();
    },
  });

  const boundRoleIds = new Set(group?.roleIds ?? []);
  const boundRoles = roles.filter((role) => boundRoleIds.has(role.id));
  const roleOptions = roles
    .filter((role) => !boundRoleIds.has(role.id))
    .map((role) => ({ label: role.name, value: role.id }));
  const isBusy = isAssigning || isUnassigning;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={group ? t('title', { name: group.name }) : t('titleFallback')}
      description={t('description')}
      primaryActionLabel={t('done')}
      onPrimaryAction={onClose}
    >
      <div className="flex flex-col gap-4">
        <div className="flex items-end gap-2">
          <Select
            label={t('bind')}
            containerClassName={`${fieldContainerClassName} flex-1`}
            className={fieldClassName}
            options={roleOptions}
            placeholder={roleOptions.length === 0 ? t('allBound') : t('selectRole')}
            disabled={isBusy || roleOptions.length === 0}
            value={selectedRoleId}
            onChange={setSelectedRoleId}
          />
          <button
            type="button"
            className="inline-flex h-8 shrink-0 items-center rounded-lg bg-focus px-4 text-sm font-medium text-white transition hover:bg-focus/90 disabled:pointer-events-none disabled:opacity-50"
            disabled={isBusy || !selectedRoleId}
            onClick={() => submitAssignRole(selectedRoleId)}
          >
            {t('bindButton')}
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {boundRoles.length === 0 ? (
            <p className="py-6 text-center text-xs font-medium text-textGray">{t('empty')}</p>
          ) : null}

          {boundRoles.map((role) => (
            <span
              key={role.id}
              className="inline-flex items-center gap-1.5 rounded-full bg-primary/15 px-2.5 py-1 text-xs font-medium text-primary"
            >
              {role.name}
              <button
                type="button"
                aria-label={t('removeAria', { name: role.name })}
                className="transition hover:text-white disabled:pointer-events-none disabled:opacity-40"
                disabled={isBusy}
                onClick={() => setPendingRemoval({ id: role.id, name: role.name })}
              >
                <span className="material-symbols-rounded text-sm!">close</span>
              </button>
            </span>
          ))}
        </div>
      </div>

      <Modal
        open={Boolean(pendingRemoval)}
        onClose={() => {
          if (!isUnassigning) {
            setPendingRemoval(null);
          }
        }}
        title={t('removeConfirm.title', { name: pendingRemoval?.name ?? '' })}
        description={t('removeConfirm.description', { group: group?.name ?? '' })}
        showCloseButton={false}
        primaryActionLabel={t('removeConfirm.submit')}
        onPrimaryAction={() => {
          if (pendingRemoval) {
            submitUnassignRole(pendingRemoval.id);
          }
        }}
        isPrimaryActionLoading={isUnassigning}
        isPrimaryActionDisabled={isUnassigning}
      >
        {null}
      </Modal>
    </Modal>
  );
}
