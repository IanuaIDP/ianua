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

import { LanguageSwitcher } from '@/components/ui/language-switcher';
import { Tooltip } from '@/components/ui/tooltip';
import { useLogout } from '@/hooks/auth/use-logout';
import { useAuthStore } from '@/store/auth-store';
import { cn } from '@/utils/cn';
import { getInitials } from '@/utils/initials';

type SidebarUserProfileProps = {
  isCollapsed?: boolean;
};

export function SidebarUserProfile({ isCollapsed = false }: SidebarUserProfileProps) {
  const t = useTranslations('dashboard.sidebar');
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const logout = useLogout();
  const userName = useAuthStore((state) => state.user?.name);
  const userEmail = useAuthStore((state) => state.user?.email);
  const userInitials = getInitials(userName || userEmail?.split('@')[0] || 'User');

  const { context, floatingStyles, refs } = useFloating({
    middleware: [offset(8), flip(), shift({ padding: 8 })],
    onOpenChange: setIsMenuOpen,
    open: isMenuOpen,
    placement: 'right-end',
    whileElementsMounted: autoUpdate,
  });

  const click = useClick(context, { enabled: isCollapsed });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getFloatingProps, getReferenceProps } = useInteractions([click, dismiss, role]);
  const setReferenceNode = useCallback(
    (node: HTMLDivElement | null) => {
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

  async function handleLogout() {
    if (isLoggingOut) {
      return;
    }

    setIsMenuOpen(false);
    setIsLoggingOut(true);

    await logout();
  }

  return (
    <div
      className={cn(
        'flex items-center p-4',
        isCollapsed ? 'justify-center p-2 w-13' : 'gap-3 px-4 py-2.5 rounded-lg',
      )}
    >
      <Tooltip content={userName || t('user')} disabled={!isCollapsed || isMenuOpen}>
        <div
          ref={isCollapsed ? setReferenceNode : undefined}
          role={isCollapsed ? 'button' : undefined}
          tabIndex={isCollapsed ? 0 : undefined}
          aria-label={isCollapsed ? t('accountMenu') : undefined}
          aria-expanded={isCollapsed ? isMenuOpen : undefined}
          className={cn(
            'flex size-9 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary',
            isCollapsed && 'cursor-pointer',
          )}
          {...(isCollapsed ? getReferenceProps() : {})}
        >
          {userInitials}
        </div>
      </Tooltip>

      {isCollapsed && isMenuOpen ? (
        <FloatingPortal>
          <div
            ref={setFloatingNode}
            style={floatingStyles}
            className="z-50"
            {...getFloatingProps()}
          >
            <button
              type="button"
              role="menuitem"
              onClick={handleLogout}
              disabled={isLoggingOut}
              className="inline-flex items-center gap-3 whitespace-nowrap rounded-xl bg-borderGray px-2.5 py-3 text-xs font-semibold text-white shadow-dropdown transition hover:bg-hoverBg disabled:cursor-not-allowed disabled:opacity-60"
            >
              <span className="material-symbols-rounded text-textGray" aria-hidden="true">
                logout
              </span>
              {t('signOut')}
            </button>
          </div>
        </FloatingPortal>
      ) : null}

      {!isCollapsed && (
        <>
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs font-medium text-white">{userName || t('user')}</p>
            <p className="truncate text-[10px] text-textGray">{userEmail}</p>
          </div>
          <LanguageSwitcher placement="top-end" variant="icon" />
          <Tooltip content={t('logOut')}>
            <button
              type="button"
              aria-label={t('logOut')}
              onClick={handleLogout}
              disabled={isLoggingOut}
              className="flex size-8 shrink-0 items-center justify-center rounded-md text-textGray transition hover:text-white disabled:cursor-not-allowed disabled:opacity-60"
            >
              <span className="material-symbols-rounded" aria-hidden="true">
                logout
              </span>
            </button>
          </Tooltip>
        </>
      )}
    </div>
  );
}
