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
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { useNotification } from '@/components/ui/notifications';
import { useLooseTranslations } from '@/hooks/i18n/use-loose-translations';
import { invalidateAuditLogQueries } from '@/lib/query-keys';
import { useAuthStore } from '@/store/auth-store';
import { cn } from '@/utils/cn';
import { ConfirmationLabel } from '@/utils/confirmation-label';
import type { DashboardActionModalContent } from '@/types/dashboard';
import { useQueryClient } from '@tanstack/react-query';

type DashboardActionIcon = {
  className?: string;
  icon: string;
};

type DashboardActionsMenuProps<Action extends string> = {
  actionIcons?: Partial<Record<Action, DashboardActionIcon>>;
  actionLabels?: Partial<Record<Action, string>>;
  actions: Action[];
  ariaLabel: string;
  customActions?: Action[];
  getActionErrorMessage?: (error: unknown, action: Action) => string;
  getActionSuccessMessage?: (action: Action) => string;
  instantActions?: Action[];
  modalContentByAction: Partial<Record<Action, DashboardActionModalContent>>;
  onActionConfirm?: (action: Action) => Promise<void> | void;
  onCustomAction?: (action: Action) => void;
  triggerLabel?: string;
};

export function DashboardActionsMenu<Action extends string>({
  actionIcons,
  actionLabels,
  actions,
  ariaLabel,
  customActions,
  getActionErrorMessage,
  getActionSuccessMessage,
  instantActions,
  modalContentByAction,
  onActionConfirm,
  onCustomAction,
  triggerLabel,
}: DashboardActionsMenuProps<Action>) {
  const t = useTranslations('dashboard.actions');
  const tLabels = useLooseTranslations('dashboard.actions.labels');
  const queryClient = useQueryClient();
  const { showNotification } = useNotification();
  const organizationSlug = useAuthStore((state) => state.user?.organizationSlug);
  const [isOpen, setIsOpen] = useState(false);
  const [confirmationValue, setConfirmationValue] = useState('');
  const [isConfirming, setIsConfirming] = useState(false);
  const [isRunningInstantAction, setIsRunningInstantAction] = useState(false);
  const [selectedAction, setSelectedAction] = useState<Action | null>(null);
  const hasActions = actions?.length > 0;
  const modalContent = selectedAction ? modalContentByAction[selectedAction] : null;
  const requiredConfirmationValue = modalContent?.confirmationValue;
  const isConfirmationValid =
    !requiredConfirmationValue || confirmationValue === requiredConfirmationValue;

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(6), flip(), shift({ padding: 8 })],
    onOpenChange: setIsOpen,
    open: isOpen,
    placement: 'bottom-end',
    whileElementsMounted: autoUpdate,
  });

  const click = useClick(context, { enabled: hasActions });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getFloatingProps, getReferenceProps } = useInteractions([click, dismiss, role]);
  const setReferenceNode = useCallback(
    (node: HTMLButtonElement | null) => {
      refs.setReference(node);
    },
    [refs],
  );
  const setFloatingNode = useCallback(
    (node: HTMLDivElement | null) => {
      refs.setFloating(node);
    },
    [refs],
  );

  function openActionModal(action: Action) {
    setIsOpen(false);
    setConfirmationValue('');
    setSelectedAction(action);
  }

  async function runInstantAction(action: Action) {
    setIsOpen(false);

    if (!onActionConfirm) {
      return;
    }

    try {
      setIsRunningInstantAction(true);
      await onActionConfirm(action);
      showNotification({
        message: getActionSuccessMessage?.(action) ?? t('succeeded'),
        type: 'success',
      });
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    } catch (error) {
      showNotification({
        message: getActionErrorMessage?.(error, action) ?? t('failed'),
        type: 'error',
      });
    } finally {
      setIsRunningInstantAction(false);
    }
  }

  function handleActionClick(action: Action) {
    if (instantActions?.includes(action)) {
      void runInstantAction(action);
      return;
    }

    if (customActions?.includes(action)) {
      setIsOpen(false);
      onCustomAction?.(action);
      return;
    }

    openActionModal(action);
  }

  function closeActionModal() {
    if (isConfirming) {
      return;
    }

    setConfirmationValue('');
    setSelectedAction(null);
  }

  async function confirmAction() {
    if (!selectedAction || !onActionConfirm) {
      closeActionModal();
      return;
    }

    try {
      setIsConfirming(true);
      await onActionConfirm(selectedAction);
      showNotification({
        message: getActionSuccessMessage?.(selectedAction) ?? t('succeeded'),
        type: 'success',
      });
      setConfirmationValue('');
      setSelectedAction(null);
      await invalidateAuditLogQueries(queryClient, organizationSlug);
    } catch (error) {
      showNotification({
        message: getActionErrorMessage?.(error, selectedAction) ?? t('failed'),
        type: 'error',
      });
    } finally {
      setIsConfirming(false);
    }
  }

  return (
    <>
      <button
        ref={setReferenceNode}
        type="button"
        aria-expanded={isOpen}
        aria-label={ariaLabel}
        disabled={!hasActions || isRunningInstantAction}
        className={cn(
          triggerLabel
            ? 'inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-borderGray bg-cardBg px-3 text-[13px] font-semibold text-white transition hover:bg-hoverBg'
            : 'inline-flex size-6 items-center justify-center rounded-md text-textGray transition',
          !triggerLabel && hasActions && !isOpen && 'hover:bg-hoverBg hover:text-white',
          !triggerLabel && hasActions && isOpen && 'text-primary',
          (!hasActions || isRunningInstantAction) && 'cursor-not-allowed opacity-40',
        )}
        {...getReferenceProps()}
      >
        {triggerLabel ? (
          <>
            {triggerLabel}
            <span className="material-symbols-rounded text-base!" aria-hidden>
              {isOpen ? 'expand_less' : 'expand_more'}
            </span>
          </>
        ) : (
          <span className="material-symbols-rounded">more_horiz</span>
        )}
      </button>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className="z-50 w-max min-w-36 overflow-hidden rounded-md bg-borderGray py-1.5 text-left shadow-dropdown"
            {...getFloatingProps()}
          >
            {actions.map((action) => {
              const icon = actionIcons?.[action];

              return (
                <button
                  key={action}
                  type="button"
                  role="menuitem"
                  onClick={() => handleActionClick(action)}
                  className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs font-semibold text-white transition hover:bg-menuHover focus:text-primary focus:outline-none"
                >
                  {icon ? (
                    <span
                      className={cn('material-symbols-rounded text-base!', icon.className)}
                      aria-hidden
                    >
                      {icon.icon}
                    </span>
                  ) : null}
                  {actionLabels?.[action] ?? (tLabels.has(action) ? tLabels(action) : action)}
                </button>
              );
            })}
          </div>
        </FloatingPortal>
      ) : null}

      <Modal
        open={Boolean(modalContent)}
        onClose={closeActionModal}
        title={modalContent?.title}
        description={modalContent?.description}
        primaryActionLabel={modalContent?.primaryActionLabel}
        onPrimaryAction={confirmAction}
        isPrimaryActionDisabled={!isConfirmationValid}
        isPrimaryActionLoading={isConfirming}
        secondaryActionLabel={modalContent?.secondaryActionLabel}
        showCloseButton={false}
      >
        {modalContent?.warningNote ? (
          <div
            className={cn(
              'flex items-center gap-2 rounded-lg border px-3 py-1 text-[10px] font-medium',
              modalContent.warningTone === 'danger'
                ? 'border-error bg-error/10 text-error'
                : 'border-orange/50 bg-orange/10 text-orange',
            )}
          >
            <span className="material-symbols-rounded text-sm!">
              {modalContent.warningTone === 'danger' ? 'error' : 'warning'}
            </span>
            <span>{modalContent.warningNote}</span>
          </div>
        ) : null}

        {modalContent?.confirmationValue ? (
          <div>
            <p className="mb-3 text-xs text-textGray">
              <ConfirmationLabel
                label={modalContent.confirmationLabel}
                value={modalContent.confirmationValue}
              />
            </p>
            <Input
              value={confirmationValue}
              onChange={(event) => setConfirmationValue(event.target.value)}
              placeholder={modalContent.confirmationPlaceholder}
              containerClassName="mb-0"
              className="max-w-48 bg-cardBg"
            />
          </div>
        ) : null}
      </Modal>
    </>
  );
}
