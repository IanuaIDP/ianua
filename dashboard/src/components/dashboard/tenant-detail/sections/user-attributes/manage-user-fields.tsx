'use client';

import { useCallback, useState } from 'react';
import {
  autoUpdate,
  flip,
  FloatingPortal,
  offset,
  shift,
  useClick,
  useDismiss,
  useFloating,
  useInteractions,
  useRole,
} from '@floating-ui/react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations } from 'next-intl';

import { DeleteUserFieldModal } from '@/components/dashboard/tenant-detail/sections/user-attributes/delete-user-field-modal';
import { UserFieldFormModal } from '@/components/dashboard/tenant-detail/sections/user-attributes/user-field-form-modal';
import { UserFieldRow } from '@/components/dashboard/tenant-detail/sections/user-attributes/user-field-row';
import { useNotification } from '@/components/ui/notifications';
import {
  declareUserAttribute,
  deleteUserAttribute,
  getApiErrorMessage,
  getUserAttributeKinds,
  getUserAttributes,
  setUserAttributeArchived,
  updateUserAttribute,
} from '@/lib/api';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import type { UserAttributeInput } from '@/schemas/user-attribute-schemas';
import type { UserAttribute, UserFieldDialog } from '@/types/user-attribute';
import { cn } from '@/utils/cn';
import { getAttributeId, toAttributeFormValues } from '@/utils/user-attribute';

type ManageUserFieldsProps = {
  canDelete?: boolean;
  canUpdate?: boolean;
  /** Whether the fields popover is open; controlled so other screens can open it. */
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  orgSlug?: string;
  tenantSlug: string;
};

/**
 * The Users page's “Manage fields” button and everything behind it: a popover
 * listing the tenant's custom user fields (active and archived), and the
 * add / edit / delete dialogs it opens.
 */
export function ManageUserFields({
  canDelete = true,
  canUpdate = true,
  isOpen,
  onOpenChange,
  orgSlug,
  tenantSlug,
}: ManageUserFieldsProps) {
  const t = useTranslations('dashboard.userFields');
  const tErrors = useTranslations('common.errors');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  // The last dialog is kept after closing so its content stays put while the
  // modal animates out; `isDialogOpen` is what decides whether it shows.
  const [dialog, setDialog] = useState<UserFieldDialog>({ mode: 'create' });
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isArchivedOpen, setIsArchivedOpen] = useState(false);

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(6), flip(), shift({ padding: 12 })],
    onOpenChange,
    open: isOpen,
    placement: 'bottom-end',
    whileElementsMounted: autoUpdate,
  });
  const click = useClick(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'dialog' });
  const { getFloatingProps, getReferenceProps } = useInteractions([click, dismiss, role]);
  const setReferenceNode = useCallback(
    (node: HTMLButtonElement | null) => refs.setReference(node),
    [refs],
  );
  const setFloatingNode = useCallback(
    (node: HTMLDivElement | null) => refs.setFloating(node),
    [refs],
  );

  const isQueryEnabled = (isOpen || isDialogOpen) && Boolean(orgSlug && tenantSlug);

  const { data: attributes = [], isLoading } = useQuery({
    enabled: isQueryEnabled,
    queryFn: () => getUserAttributes(orgSlug ?? '', tenantSlug, { includeArchived: true }),
    queryKey: ['tenant-user-attributes', orgSlug, tenantSlug, true],
  });

  const { data: kinds = [] } = useQuery({
    enabled: isQueryEnabled,
    queryFn: () => getUserAttributeKinds(orgSlug ?? '', tenantSlug),
    // The catalogue is the same answer for every tenant on a given build, so
    // it is worth holding on to once fetched.
    queryKey: ['tenant-user-attribute-kinds', orgSlug, tenantSlug],
    staleTime: Infinity,
  });

  const activeFields = attributes.filter((attribute) => !attribute.archived);
  const archivedFields = attributes.filter((attribute) => attribute.archived);

  async function refreshFields() {
    await queryClient.invalidateQueries({
      queryKey: ['tenant-user-attributes', orgSlug, tenantSlug],
    });
    await queryClient.invalidateQueries({ queryKey: ['tenant-users', orgSlug, tenantSlug] });
    await invalidateAuditLogQueries(queryClient, orgSlug);
  }

  function requireOrg() {
    if (!orgSlug) {
      throw new Error(tErrors('organizationMissing'));
    }

    return orgSlug;
  }

  function notifyFailure(error: unknown, fallback: string) {
    showNotification({ message: getApiErrorMessage(error, fallback), type: 'error' });
  }

  /** Opens a dialog in place of the popover. */
  function openDialog(next: UserFieldDialog) {
    onOpenChange(false);
    setDialog(next);
    setIsDialogOpen(true);
  }

  /** Closes the dialog and returns to the list it was opened from. */
  function closeDialog() {
    setIsDialogOpen(false);
    onOpenChange(true);
  }

  const { isPending: isDeclaring, mutate: submitDeclare } = useMutation({
    mutationFn: (payload: UserAttributeInput) =>
      declareUserAttribute(requireOrg(), tenantSlug, payload),
    onError: (error) => notifyFailure(error, t('toasts.addFailed')),
    onSuccess: async () => {
      closeDialog();
      showNotification({ message: t('toasts.added'), type: 'success' });
      await refreshFields();
    },
  });

  const { isPending: isUpdating, mutate: submitUpdate } = useMutation({
    mutationFn: ({
      attribute,
      payload,
    }: {
      attribute: UserAttribute;
      payload: UserAttributeInput;
    }) => updateUserAttribute(requireOrg(), tenantSlug, attribute, payload),
    onError: (error) => notifyFailure(error, t('toasts.updateFailed')),
    onSuccess: async () => {
      closeDialog();
      showNotification({ message: t('toasts.updated'), type: 'success' });
      await refreshFields();
    },
  });

  const {
    isPending: isTogglingListed,
    mutate: submitListed,
    variables: listedVariables,
  } = useMutation({
    mutationFn: ({ attribute, listed }: { attribute: UserAttribute; listed: boolean }) =>
      updateUserAttribute(requireOrg(), tenantSlug, attribute, {
        ...toAttributeFormValues(attribute),
        listed,
      }),
    onError: (error) => notifyFailure(error, t('toasts.columnFailed')),
    onSuccess: refreshFields,
  });

  const {
    isPending: isArchiving,
    mutate: submitArchive,
    variables: archiveVariables,
  } = useMutation({
    mutationFn: ({ archived, attribute }: { archived: boolean; attribute: UserAttribute }) =>
      setUserAttributeArchived(requireOrg(), tenantSlug, attribute, archived),
    onError: (error) => notifyFailure(error, t('toasts.updateFailed')),
    onSuccess: async (_result, { archived }) => {
      showNotification({
        message: archived ? t('toasts.archived') : t('toasts.restored'),
        type: 'success',
      });

      if (archived) {
        setIsArchivedOpen(true);
      }

      await refreshFields();
    },
  });

  const { isPending: isDeleting, mutate: submitDelete } = useMutation({
    mutationFn: (attribute: UserAttribute) =>
      deleteUserAttribute(requireOrg(), tenantSlug, attribute),
    onError: (error) => notifyFailure(error, t('toasts.deleteFailed')),
    onSuccess: async (valuesDeleted) => {
      closeDialog();
      showNotification({ message: t('toasts.deleted', { count: valuesDeleted }), type: 'success' });
      await refreshFields();
    },
  });

  function handleDialogClose() {
    if (isDeclaring || isUpdating || isDeleting) {
      return;
    }

    closeDialog();
  }

  function isRowBusy(attribute: UserAttribute) {
    const id = getAttributeId(attribute);

    return Boolean(
      (isTogglingListed && listedVariables && getAttributeId(listedVariables.attribute) === id) ||
      (isArchiving && archiveVariables && getAttributeId(archiveVariables.attribute) === id),
    );
  }

  function renderFieldRow(attribute: UserAttribute) {
    return (
      <UserFieldRow
        key={getAttributeId(attribute)}
        attribute={attribute}
        canDelete={canDelete}
        canUpdate={canUpdate}
        isBusy={isRowBusy(attribute)}
        onArchiveChange={(field, archived) => submitArchive({ archived, attribute: field })}
        onDeleteClick={(field) => openDialog({ attribute: field, mode: 'delete' })}
        onEditClick={(field) => openDialog({ attribute: field, mode: 'edit' })}
        onListedChange={(field, listed) => submitListed({ attribute: field, listed })}
      />
    );
  }

  return (
    <>
      <button
        ref={setReferenceNode}
        type="button"
        aria-expanded={isOpen}
        className="inline-flex h-8 shrink-0 items-center gap-2 whitespace-nowrap rounded-lg border border-borderGray bg-surfaceChip pl-4 pr-2.5 text-sm font-medium text-white transition hover:bg-hoverBg"
        {...getReferenceProps()}
      >
        {t('manage.button')}
        <span className="material-symbols-rounded text-xl!" aria-hidden="true">
          {isOpen ? 'arrow_drop_up' : 'arrow_drop_down'}
        </span>
      </button>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            aria-label={t('manage.title')}
            className="z-40 flex max-h-[min(560px,calc(100vh-120px))] w-112 max-w-[calc(100vw-24px)] flex-col rounded-lg border border-borderGray bg-cardBg p-4 shadow-dropdown"
            {...getFloatingProps()}
          >
            <div className="flex shrink-0 items-center justify-between gap-3">
              <h3 className="text-base font-semibold text-white">{t('manage.title')}</h3>
              {canUpdate ? (
                <button
                  type="button"
                  className="inline-flex items-center gap-1.5 text-sm font-medium text-primary transition hover:text-primary/80"
                  onClick={() => openDialog({ mode: 'create' })}
                >
                  <span className="material-symbols-rounded text-xl!" aria-hidden="true">
                    add
                  </span>
                  {t('manage.add')}
                </button>
              ) : null}
            </div>

            <div className="scrollbar-hidden mt-3 min-h-0 overflow-y-auto">
              {isLoading ? (
                <p className="py-2 text-center text-xs font-medium text-textGray">{t('loading')}</p>
              ) : null}

              {!isLoading && attributes.length === 0 ? (
                <p className="flex items-center justify-center gap-2 py-1 text-xs font-medium text-textGray">
                  <span className="material-symbols-rounded text-lg!" aria-hidden="true">
                    announcement
                  </span>
                  {t('manage.empty')}
                </p>
              ) : null}

              {activeFields.length > 0 ? (
                <ul className="flex flex-col gap-1.5">{activeFields.map(renderFieldRow)}</ul>
              ) : null}

              {archivedFields.length > 0 ? (
                <div className={cn(activeFields.length > 0 && 'mt-3')}>
                  <button
                    type="button"
                    aria-expanded={isArchivedOpen}
                    className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-textGray transition hover:text-white"
                    onClick={() => setIsArchivedOpen(!isArchivedOpen)}
                  >
                    {t('manage.archived')}
                    <span className="material-symbols-rounded text-base!" aria-hidden="true">
                      {isArchivedOpen ? 'keyboard_arrow_up' : 'keyboard_arrow_down'}
                    </span>
                  </button>

                  {isArchivedOpen ? (
                    <ul className="mt-1.5 flex flex-col gap-1.5">
                      {archivedFields.map(renderFieldRow)}
                    </ul>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>
        </FloatingPortal>
      ) : null}

      <UserFieldFormModal
        attribute={dialog.mode === 'edit' ? dialog.attribute : undefined}
        isSubmitting={dialog.mode === 'edit' ? isUpdating : isDeclaring}
        kinds={kinds}
        open={isDialogOpen && dialog.mode !== 'delete'}
        onClose={handleDialogClose}
        onSubmit={(payload) =>
          dialog.mode === 'edit'
            ? submitUpdate({ attribute: dialog.attribute, payload })
            : submitDeclare(payload)
        }
      />

      <DeleteUserFieldModal
        isSubmitting={isDeleting}
        open={isDialogOpen && dialog.mode === 'delete'}
        onClose={handleDialogClose}
        onConfirm={() => {
          if (dialog.mode === 'delete') {
            submitDelete(dialog.attribute);
          }
        }}
      />
    </>
  );
}
