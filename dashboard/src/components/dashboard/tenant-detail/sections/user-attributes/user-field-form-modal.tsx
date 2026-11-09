'use client';

import { useTranslations } from 'next-intl';

import { UserAttributeForm } from '@/components/dashboard/tenant-detail/sections/user-attributes/user-attribute-form';
import { Modal } from '@/components/ui/modal';
import { USER_ATTRIBUTE_FORM_ID } from '@/constants/user-attribute';
import type { UserAttributeInput } from '@/schemas/user-attribute-schemas';
import type { UserAttribute, UserAttributeKindOption } from '@/types/user-attribute';
import { getAttributeId, toAttributeFormValues } from '@/utils/user-attribute';

type UserFieldFormModalProps = {
  /** The field being edited; leave it out to add a new one. */
  attribute?: UserAttribute;
  isSubmitting: boolean;
  kinds: UserAttributeKindOption[];
  onClose: () => void;
  onSubmit: (payload: UserAttributeInput) => void;
  open: boolean;
};

/** “Add a field” or, given a field, “Edit a field”. */
export function UserFieldFormModal({
  attribute,
  isSubmitting,
  kinds,
  onClose,
  onSubmit,
  open,
}: UserFieldFormModalProps) {
  const t = useTranslations('dashboard.userFields');
  const isEditing = Boolean(attribute);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEditing ? t('formModal.editTitle') : t('formModal.addTitle')}
      description={isEditing ? t('formModal.editDescription') : t('formModal.addDescription')}
      showCloseButton={false}
      primaryActionLabel={isEditing ? t('save') : t('formModal.addSubmit')}
      primaryActionType="submit"
      primaryActionForm={USER_ATTRIBUTE_FORM_ID}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
      onSecondaryAction={onClose}
    >
      <UserAttributeForm
        key={attribute ? getAttributeId(attribute) : 'new'}
        defaultValues={attribute ? toAttributeFormValues(attribute) : undefined}
        isEditing={isEditing}
        isSubmitting={isSubmitting}
        kinds={kinds}
        onSubmit={onSubmit}
      />
    </Modal>
  );
}
