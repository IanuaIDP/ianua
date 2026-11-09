'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { AttributeControlField } from '@/components/dashboard/tenant-detail/sections/user-attributes/attribute-control-field';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { EDIT_USER_FIELDS_FORM_ID } from '@/constants/user-attribute';
import {
  getApiErrorMessage,
  getUserAttributes,
  getUserAttributeValues,
  setUserAttributeValue,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { TenantUser } from '@/types/tenant-user';
import type { UserAttributeValues } from '@/types/user-attribute';
import {
  getAttributeId,
  isBlankAttributeValue,
  isSameAttributeValue,
} from '@/utils/user-attribute';

type EditUserFieldsModalProps = {
  canUpdate?: boolean;
  onClose: () => void;
  onManageFieldsClick: () => void;
  orgSlug?: string;
  tenantSlug: string;
  user: TenantUser | null;
};

/** Stable, so comparing it against the draft's source cannot loop. */
const noValues: UserAttributeValues = {};

export function EditUserFieldsModal({
  canUpdate = true,
  onClose,
  onManageFieldsClick,
  orgSlug,
  tenantSlug,
  user,
}: EditUserFieldsModalProps) {
  const t = useTranslations('dashboard.userFields');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const open = Boolean(user);
  const [draft, setDraft] = useState<UserAttributeValues>(noValues);
  const [source, setSource] = useState<{ userId: string; values: UserAttributeValues } | null>(
    null,
  );

  const { data: attributes = [], isLoading: isLoadingFields } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: () => getUserAttributes(orgSlug ?? '', tenantSlug),
    queryKey: ['tenant-user-attributes', orgSlug, tenantSlug, false],
  });

  const { data: stored = noValues, isLoading: isLoadingValues } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug && user),
    queryFn: () => getUserAttributeValues(orgSlug ?? '', tenantSlug, user?.id ?? ''),
    queryKey: ['tenant-user-attribute-values', orgSlug, tenantSlug, user?.id],
  });

  const editable = attributes.filter((attribute) => !attribute.archived);

  // The draft starts from what is stored, and is rebuilt whenever the dialog
  // is pointed at another user or the stored values arrive.
  if (user && (source?.userId !== user.id || source.values !== stored)) {
    setSource({ userId: user.id, values: stored });
    setDraft(stored);
  }

  const changed = editable.filter(
    (attribute) =>
      !isSameAttributeValue(
        draft[getAttributeId(attribute)] ?? null,
        stored[getAttributeId(attribute)] ?? null,
      ),
  );

  const { isPending: isSaving, mutate: submitValues } = useMutation({
    mutationFn: async () => {
      if (!orgSlug || !user) {
        throw new Error(tErrors('organizationMissing'));
      }

      for (const attribute of changed) {
        const next = draft[getAttributeId(attribute)] ?? null;

        await setUserAttributeValue(
          orgSlug,
          tenantSlug,
          user.id,
          attribute,
          isBlankAttributeValue(next) ? null : next,
        );
      }
    },
    onError: (error) => {
      showNotification({
        message: getApiErrorMessage(error, t('saveFailed')),
        type: 'error',
      });
    },
    onSuccess: async () => {
      showNotification({ message: t('saved'), type: 'success' });
      await queryClient.invalidateQueries({
        queryKey: ['tenant-user-attribute-values', orgSlug, tenantSlug],
      });
      await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
      await invalidateAuditLogQueries(queryClient, orgSlug);
      onClose();
    },
  });

  const isLoading = isLoadingFields || isLoadingValues;

  return (
    <Modal
      open={open}
      onClose={() => {
        if (isSaving) {
          return;
        }

        onClose();
      }}
      title={t('editTitle')}
      description={t('editDescription')}
      showCloseButton={false}
      primaryActionLabel={canUpdate && editable.length > 0 ? t('save') : undefined}
      primaryActionType="submit"
      primaryActionForm={EDIT_USER_FIELDS_FORM_ID}
      isPrimaryActionLoading={isSaving}
      isPrimaryActionDisabled={isSaving || changed.length === 0}
    >
      {isLoading ? <p className="text-xs font-medium text-textGray">{t('loading')}</p> : null}

      {!isLoading && editable.length === 0 ? (
        <div className="rounded-lg border border-borderGray bg-surfaceInset p-4">
          <p className="text-xs font-medium text-textGray">{t('none')}</p>
          <button
            type="button"
            className="mt-2 text-xs font-semibold text-focus transition hover:text-focus/80"
            onClick={onManageFieldsClick}
          >
            {t('manage.button')}
          </button>
        </div>
      ) : null}

      {!isLoading && editable.length > 0 ? (
        <form
          id={EDIT_USER_FIELDS_FORM_ID}
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            submitValues();
          }}
        >
          {editable.map((attribute) => (
            <AttributeControlField
              key={getAttributeId(attribute)}
              attribute={attribute}
              disabled={!canUpdate || isSaving}
              value={draft[getAttributeId(attribute)] ?? null}
              onChange={(next) =>
                setDraft((current) => ({ ...current, [getAttributeId(attribute)]: next }))
              }
            />
          ))}
        </form>
      ) : null}
    </Modal>
  );
}
