import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { Notification, NotificationType } from '@/types/notification';
import { cn } from '@/utils/cn';

import { hasRichNotificationContent } from './notification-content';

type NotificationStackProps = {
  compactSlotNotificationId?: number;
  hiddenNotificationCount: number;
  notifications: Notification[];
  notificationCount: number;
  onDismiss: (id: number) => void;
  onDismissAll: () => void;
};

const notificationContainerClasses: Record<NotificationType, string> = {
  default: 'border-transparent bg-white text-appBg',
  error: 'border-error/50 bg-cardBg text-error',
  success: 'border-primary/50 bg-cardBg text-primary',
};

const notificationOverlayClasses: Record<NotificationType, string | undefined> = {
  default: undefined,
  error: 'bg-error/20',
  success: 'bg-primary/20',
};

const notificationIconClasses: Record<NotificationType, string> = {
  default: 'text-appBg',
  error: 'text-error',
  success: 'text-primary',
};

const notificationIconNames: Record<NotificationType, string> = {
  default: 'info',
  error: 'error',
  success: 'check_circle',
};

const notificationCloseButtonClasses: Record<NotificationType, string> = {
  default: 'text-textGray',
  error: 'text-error',
  success: 'text-primary',
};

function DismissAllButton({ onDismissAll }: Pick<NotificationStackProps, 'onDismissAll'>) {
  const t = useTranslations('dashboard.toasts');

  return (
    <button
      type="button"
      onClick={onDismissAll}
      className="rounded-lg border border-borderGray bg-hoverBg px-4 py-2 text-sm font-semibold text-white shadow-dropdown transition hover:bg-cardBg"
    >
      {t('dismissAll')}
    </button>
  );
}

function NotificationCloseButton({
  className,
  notificationId,
  onDismiss,
}: {
  className?: string;
  notificationId: number;
  onDismiss: (id: number) => void;
}) {
  const t = useTranslations('dashboard.toasts');

  return (
    <button
      type="button"
      aria-label={t('dismiss')}
      onClick={() => onDismiss(notificationId)}
      className={className}
    >
      <span className="material-symbols-rounded" aria-hidden>
        close
      </span>
    </button>
  );
}

function RichNotificationContent({
  hiddenNotificationCount,
  notification,
  onDismiss,
}: {
  hiddenNotificationCount: number;
  notification: Notification;
  onDismiss: (id: number) => void;
}) {
  const t = useTranslations('dashboard.toasts');

  return (
    <div>
      <span
        className="absolute bottom-4 left-0 top-4 w-0.5 rounded-r-full bg-focus shadow-focus-line-glow"
        aria-hidden
      />
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="break-words text-sm font-semibold text-white">
            {notification.title || notification.message}
          </h2>
          <p className="mt-1 text-xs font-medium text-textGray">
            {notification.body || notification.message}
          </p>
          {hiddenNotificationCount > 0 ? (
            <p className="mt-2.5 text-[10px] font-medium text-white">
              {t('more', { count: hiddenNotificationCount })}
            </p>
          ) : null}
        </div>
        <NotificationCloseButton
          notificationId={notification.id}
          onDismiss={onDismiss}
          className="flex size-7 shrink-0 items-center justify-center rounded-md text-textGray transition hover:text-white"
        />
      </div>
    </div>
  );
}

function SimpleNotificationContent({
  notification,
  onDismiss,
}: {
  notification: Notification;
  onDismiss: (id: number) => void;
}) {
  return (
    <>
      <span
        className={cn('material-symbols-rounded', notificationIconClasses[notification.type])}
        aria-hidden
      >
        {notificationIconNames[notification.type]}
      </span>
      <span className="min-w-0 flex-1 text-left">{notification.message}</span>
      <NotificationCloseButton
        notificationId={notification.id}
        onDismiss={onDismiss}
        className={cn(
          'flex size-5 shrink-0 items-center justify-center rounded-md transition',
          notificationCloseButtonClasses[notification.type],
        )}
      />
    </>
  );
}

function NotificationActionLink({
  actionHref,
  actionLabel,
  onClick,
}: {
  actionHref: string;
  actionLabel?: string;
  onClick: () => void;
}) {
  const t = useTranslations('dashboard.toasts');

  return (
    <Link
      href={actionHref}
      onClick={onClick}
      className="mt-1 flex items-center justify-end gap-2 text-xs font-medium text-primary transition hover:text-white"
    >
      {actionLabel || t('seeAll')}
      <span className="material-symbols-rounded text-3xl" aria-hidden>
        arrow_forward
      </span>
    </Link>
  );
}

function NotificationCard({
  hiddenNotificationCount,
  notification,
  onDismiss,
}: {
  hiddenNotificationCount: number;
  notification: Notification;
  onDismiss: (id: number) => void;
}) {
  const hasRichContent = hasRichNotificationContent(notification);

  return (
    <div className="w-full">
      <div
        role={notification.type === 'error' ? 'alert' : 'status'}
        className={cn(
          'relative isolate w-full overflow-hidden rounded-lg border bg-cardBg px-3 py-[11.5px] shadow-dropdown sm:px-4',
          hasRichContent
            ? 'border-borderGray text-left'
            : 'flex items-center gap-2 text-center text-sm font-medium sm:gap-3',
          !hasRichContent && notificationContainerClasses[notification.type],
        )}
      >
        {!hasRichContent && notificationOverlayClasses[notification.type] ? (
          <span
            className={cn(
              'pointer-events-none absolute inset-0 -z-10',
              notificationOverlayClasses[notification.type],
            )}
            aria-hidden
          />
        ) : null}
        {hasRichContent ? (
          <RichNotificationContent
            hiddenNotificationCount={hiddenNotificationCount}
            notification={notification}
            onDismiss={onDismiss}
          />
        ) : (
          <SimpleNotificationContent notification={notification} onDismiss={onDismiss} />
        )}
      </div>
    </div>
  );
}

export function NotificationStack({
  compactSlotNotificationId,
  hiddenNotificationCount,
  notifications,
  notificationCount,
  onDismiss,
  onDismissAll,
}: NotificationStackProps) {
  const notificationWithAction = notifications.findLast((notification) => notification.actionHref);

  return (
    <div
      className="fixed inset-x-4 z-60 flex flex-col items-end gap-2 sm:inset-x-auto sm:right-4 sm:bottom-5.5 sm:w-100"
      style={{ bottom: 'calc(1.375rem + env(safe-area-inset-bottom))' }}
    >
      {notificationCount > 1 ? <DismissAllButton onDismissAll={onDismissAll} /> : null}
      {notifications.map((notification) => (
        <NotificationCard
          key={notification.id}
          hiddenNotificationCount={
            notification.id === compactSlotNotificationId ? hiddenNotificationCount : 0
          }
          notification={notification}
          onDismiss={onDismiss}
        />
      ))}
      {notificationWithAction?.actionHref ? (
        <NotificationActionLink
          actionHref={notificationWithAction.actionHref}
          actionLabel={notificationWithAction.actionLabel}
          onClick={() => onDismiss(notificationWithAction.id)}
        />
      ) : null}
    </div>
  );
}
