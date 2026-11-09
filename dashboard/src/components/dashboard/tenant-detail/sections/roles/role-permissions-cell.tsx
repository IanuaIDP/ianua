'use client';

import { useCallback, useState } from 'react';
import {
  autoUpdate,
  flip,
  FloatingPortal,
  offset,
  shift,
  safePolygon,
  useDismiss,
  useFloating,
  useFocus,
  useHover,
  useInteractions,
  useRole,
} from '@floating-ui/react';
import { useTranslations } from 'next-intl';

import { summarizeRolePermissions } from '@/lib/roles/permission-format';
import type { Role } from '@/types/role';
import { cn } from '@/utils/cn';
import { VISIBLE_GROUP_COUNT } from '@/constants/role';

type RolePermissionsCellProps = {
  role: Role;
};

export function RolePermissionsCell({ role }: RolePermissionsCellProps) {
  const t = useTranslations('dashboard.tenantRoles');
  const [isOpen, setIsOpen] = useState(false);
  const groups = summarizeRolePermissions(role);
  const visibleLabels = groups.slice(0, VISIBLE_GROUP_COUNT).map((group) => group.label);
  const hiddenCount = groups.length - visibleLabels.length;

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(8), flip(), shift({ padding: 8 })],
    onOpenChange: setIsOpen,
    open: isOpen,
    placement: 'bottom-start',
    whileElementsMounted: autoUpdate,
  });

  const hover = useHover(context, {
    enabled: groups.length > 0,
    handleClose: safePolygon(),
  });
  const focus = useFocus(context, { enabled: groups.length > 0 });
  const dismiss = useDismiss(context);
  const tooltipRole = useRole(context, { role: 'tooltip' });
  const { getFloatingProps, getReferenceProps } = useInteractions([
    hover,
    focus,
    dismiss,
    tooltipRole,
  ]);
  const setReferenceNode = useCallback(
    (node: HTMLSpanElement | null) => {
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

  if (!groups.length) {
    return <span className="text-white">-</span>;
  }

  return (
    <>
      <span
        ref={setReferenceNode}
        tabIndex={0}
        className="inline-block max-w-full truncate border-b border-dotted border-primary/60 text-xs font-semibold text-primary outline-none hover:border-primary"
        {...getReferenceProps()}
      >
        {visibleLabels.join(', ')}
        {hiddenCount > 0 ? `, +${hiddenCount}` : ''}
      </span>

      {isOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className="z-50 flex max-h-80 w-64 flex-col rounded-lg border border-borderGray bg-appBg p-3 shadow-lg"
            {...getFloatingProps()}
          >
            <div className="mb-2 flex shrink-0 items-center justify-between">
              <span className="text-xs font-semibold text-white">{t('columns.permissions')}</span>
              <span className="text-xs font-semibold text-focus">
                {t('selected', { count: role.permissionsCount })}
              </span>
            </div>
            <div className="overflow-y-auto rounded-lg border border-borderGray">
              {groups.map((group, index) => (
                <div
                  key={group.resource}
                  className={cn('px-3 py-2', index > 0 && 'border-t border-borderGray')}
                >
                  <p className="text-xs font-medium text-textGray">{group.label}</p>
                  <p className="mt-1 text-sm font-medium text-white">{group.actions.join(', ')}</p>
                </div>
              ))}
            </div>
          </div>
        </FloatingPortal>
      ) : null}
    </>
  );
}
