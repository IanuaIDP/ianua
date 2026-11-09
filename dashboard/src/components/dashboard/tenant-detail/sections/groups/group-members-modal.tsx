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
import {
  addGroupMember,
  getApiErrorMessage,
  getGroupMembers,
  getTenantUsers,
  removeGroupMember,
} from '@/lib/api';
import type { Group, GroupMember } from '@/types/group';

type GroupMembersModalProps = {
  group: Group | null;
  onClose: () => void;
  orgSlug?: string;
  tenantSlug: string;
};

export function GroupMembersModal({ group, onClose, orgSlug, tenantSlug }: GroupMembersModalProps) {
  const t = useTranslations('dashboard.groups.members');
  const tErrors = useTranslations('common.errors');
  const open = Boolean(group);
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const [wasOpen, setWasOpen] = useState(open);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [pendingRemoval, setPendingRemoval] = useState<GroupMember | null>(null);

  if (open !== wasOpen) {
    setWasOpen(open);

    if (open) {
      setSelectedUserId('');
    }
  }

  const {
    data: members = [],
    error: membersError,
    isLoading,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug && group),
    queryFn: () => getGroupMembers(orgSlug ?? '', tenantSlug, group?.id ?? ''),
    queryKey: ['tenant-group-members', orgSlug, tenantSlug, group?.id],
  });

  const { data: users } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getTenantUsers(orgSlug ?? '', tenantSlug, { limit: 100 }),
    queryKey: ['tenant-users', orgSlug, tenantSlug, 'group-member-options'],
  });

  async function invalidateMembers() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-group-members', orgSlug, tenantSlug, group?.id],
    });
  }

  const { isPending: isAdding, mutate: submitAddMember } = useMutation({
    mutationFn: (userId: string) => {
      if (!orgSlug || !group) {
        throw new Error(tErrors('organizationMissing'));
      }

      return addGroupMember(orgSlug, tenantSlug, group.id, { id: userId, kind: 'user' });
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('addFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      setSelectedUserId('');
      showNotification({ message: t('added'), type: 'success' });
      await invalidateMembers();
    },
  });

  const { isPending: isRemoving, mutate: submitRemoveMember } = useMutation({
    mutationFn: (member: GroupMember) => {
      if (!orgSlug || !group) {
        throw new Error(tErrors('organizationMissing'));
      }

      return removeGroupMember(orgSlug, tenantSlug, group.id, member);
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
      await invalidateMembers();
    },
  });

  const memberIds = new Set(members.map((member) => member.id));
  const userOptions = (users?.items ?? [])
    .filter((user) => !memberIds.has(user.id))
    .map((user) => ({ label: `${user.displayName} (${user.email})`, value: user.id }));
  const isBusy = isAdding || isRemoving;

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
            label={t('add')}
            containerClassName={`${fieldContainerClassName} flex-1`}
            className={fieldClassName}
            options={userOptions}
            placeholder={userOptions.length === 0 ? t('everyoneIn') : t('selectUser')}
            disabled={isBusy || userOptions.length === 0}
            value={selectedUserId}
            onChange={setSelectedUserId}
          />
          <button
            type="button"
            className="inline-flex h-8 shrink-0 items-center rounded-lg bg-focus px-4 text-sm font-medium text-white transition hover:bg-focus/90 disabled:pointer-events-none disabled:opacity-50"
            disabled={isBusy || !selectedUserId}
            onClick={() => submitAddMember(selectedUserId)}
          >
            {t('addButton')}
          </button>
        </div>

        <div className="flex flex-col gap-1.5">
          {isLoading ? (
            <p className="py-6 text-center text-xs font-medium text-textGray">{t('loading')}</p>
          ) : null}

          {membersError ? (
            <p className="py-6 text-center text-xs font-medium text-error">
              {getApiErrorMessage(membersError, t('loadFailed'))}
            </p>
          ) : null}

          {!isLoading && !membersError && members.length === 0 ? (
            <p className="py-6 text-center text-xs font-medium text-textGray">{t('empty')}</p>
          ) : null}

          {members.map((member) => (
            <div
              key={`${member.kind}:${member.id}`}
              className="flex items-center justify-between gap-3 rounded-lg border border-borderGray bg-surfaceRaised px-3 py-2"
            >
              <div className="flex min-w-0 flex-col">
                <span className="truncate text-xs font-semibold text-white">
                  {member.displayName}
                </span>
                <span className="text-[10px] font-medium text-textGray">
                  {t(`kinds.${member.kind}`)} · {t('joined', { date: member.joinedAt })}
                </span>
              </div>
              <button
                type="button"
                aria-label={t('removeAria', { name: member.displayName })}
                className="flex size-7 shrink-0 items-center justify-center rounded-md text-textGray transition hover:bg-hoverBg hover:text-error disabled:pointer-events-none disabled:opacity-40"
                disabled={isBusy}
                onClick={() => setPendingRemoval(member)}
              >
                <span className="material-symbols-rounded text-base!">close</span>
              </button>
            </div>
          ))}
        </div>
      </div>

      <Modal
        open={Boolean(pendingRemoval)}
        onClose={() => {
          if (!isRemoving) {
            setPendingRemoval(null);
          }
        }}
        title={t('removeConfirm.title', { name: pendingRemoval?.displayName ?? '' })}
        description={t('removeConfirm.description', { group: group?.name ?? '' })}
        showCloseButton={false}
        primaryActionLabel={t('removeConfirm.submit')}
        onPrimaryAction={() => {
          if (pendingRemoval) {
            submitRemoveMember(pendingRemoval);
          }
        }}
        isPrimaryActionLoading={isRemoving}
        isPrimaryActionDisabled={isRemoving}
      >
        {null}
      </Modal>
    </Modal>
  );
}
